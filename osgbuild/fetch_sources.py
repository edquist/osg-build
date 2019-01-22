"""Fetch sources from the upstream cache and combine them with sources from
the osg/ dir in the package.

"""

# pylint: disable=W0614
from __future__ import absolute_import
from __future__ import print_function
import collections
import fnmatch
import logging
import glob
import re
import os
import tempfile
import shutil
import subprocess
import sys
try:
    from six.moves import urllib
except ImportError:
    from .six.moves import urllib


from . import constants as C
from .error import Error, GlobNotFoundError
from . import utils


if __name__ != "__main__":
    log = logging.getLogger(__name__)
else:
    log = logging.getLogger()
    logging.basicConfig(format="%(message)s", level=logging.INFO)


def _get_required_attr(kw, key, line):
    if key not in kw:
        raise Error("No %s specified for line: %s" % (key, line))
    return kw[key]

def _required(item, key, line):
    if item is None:
        raise Error("No %s specified for line: %s" % (key, line))

def _mk_prefix(name, tag, tarball):
    if tarball:
        if not tarball.endswith('.tar.gz'):
            raise Error("tarball must end with .tar.gz: '%s'" % tarball)
        prefix = tarball[:-len('.tar.gz')]
    else:
        tarball_version = re.match(r'(?:v(?=\d))?([^-]+)', tag).group(1)
        prefix = "%s-%s" % (name, tarball_version)
    return prefix

def fetch_github_source(kw, destdir='.', nocheck=False, want_spec=False,
                        line=''):
    repo = _get_required_attr(kw, 'repo', line)
    m = re.match(r"([^\s/]+)/([^\s/]+?)(?:.git)?$", repo)
    if not m:
        raise Error("Repo syntax must be owner/project: %s" % line)
    url = "https://github.com/" + repo
    newkw = dict(kw, url=url)
    return fetch_git_source(newkw, destdir, nocheck, want_spec, line)

# fetch handlers should be defined like:
#
#   fetch_xyz_source(
#       required_named_or_positional_arg, ...,
#       optional_named_or_positional_arg=None, ...,
#       ops=None,  # marks end of positional (unnamed) args allowed
#                  # (another positional arg here will raise an exception)
#       optional_named_arg=None, ...,
#       **kw  # this maybe should not be listed, or should ensure empty
#       )

def nvl(arg, default):
    return default if arg is None else arg

def fetch_git_source(url, tag, hash=None, ops=None,
        name=None, spec=None, tarball=None, **kw):
    name = name or re.sub(r'\.git$', '', os.path.basename(url))
    ops.nocheck or _required(hash, 'hash', ops.line)
    spec = ops.want_spec and nvl(spec, "rpm/%s.spec" % name)
    prefix = _mk_prefix(name, tag, tarball)

    return run_with_tmp_git_dir(ops.destdir, lambda:
        git_archive_remote_ref(url, tag, hash, prefix, spec, ops))

def run_with_tmp_git_dir(destdir, call):
    git_dir = tempfile.mkdtemp(dir=destdir)
    old_git_dir = update_env('GIT_DIR', git_dir)
    try:
        return call()
    finally:
        shutil.rmtree(git_dir)
        update_env('GIT_DIR', old_git_dir)

def update_env(key, val):
    oldval = os.environ.get(key)
    if val is None:
        del os.environ[key]
    else:
        os.environ[key] = val
    return oldval

def git_archive_remote_ref(url, tag, hash, prefix, spec, ops):
    utils.checked_call(['git', 'init', '--bare'])
    utils.checked_call(['git', 'remote', 'add', 'origin', url])
    utils.checked_call(['git', 'fetch', '--depth=1', 'origin', tag])
    got_sha = utils.checked_backtick(['git', 'rev-parse', 'FETCH_HEAD'])
    if hash or not ops.nocheck:
        check_git_hash(url, tag, hash, got_sha, ops.nocheck)

    dest_tar_gz = "%s/%s.tar.gz" % (ops.destdir, prefix)
    git_archive_cmd = ['git', 'archive', '--format=tar',
                                         '--prefix=%s/' % prefix, got_sha]
    gzip_cmd = ['gzip', '-n']

    with open(dest_tar_gz, "w") as destf:
        utils.checked_pipeline(git_archive_cmd, gzip_cmd, stdout=destf)

    if spec:
        spec = try_get_spec(ops.destdir, got_sha, spec)

    return got_sha, dest_tar_gz, spec

def try_get_spec(destdir, got_sha, spec):
    dest_spec = "%s/%s" % (destdir, os.path.basename(spec))
    spec_rev = '%s:%s' % (got_sha, spec)
    with open(dest_spec, "w") as specf:
        rc = utils.unchecked_call(['git', 'show', spec_rev], stdout=specf)
    if rc:
        log.debug("No spec file found under %s" % spec_rev)
        return None
    else:
        return dest_spec

def check_git_hash(url, tag, sha, got_sha, nocheck):
    efmt = "Hash mismatch for %s tag %s\n    expected: %s\n    actual:   %s"
    if sha != got_sha and deref_git_sha(sha) != deref_git_sha(got_sha):
        msg = efmt % (url, tag, sha, got_sha)
        if nocheck:
            log.warning(msg + "\n    (ignored)")
        else:
            raise Error(msg)


def chunked_read(handle, size):
    chunk = handle.read(size)
    while chunk:
        yield chunk
        chunk = handle.read(size)

def download_uri(uri, output_path):
    log.info('Retrieving ' + uri)
    try:
        handle = urllib.request.urlopen(uri)
    except urllib.error.URLError as err:
        raise Error("Unable to download %s\n%s" % (uri, err))

    try:
        with open(output_path, 'wb') as desthandle:
            for chunk in chunked_read(handle, 64 * 1024):
                desthandle.write(chunk)
    except EnvironmentError as err:
        raise Error("Unable to save downloaded file to %s\n%s" % (output_path, err))


# common fetch options not found in .source line
FetchOptions = collections.namedtuple(
    'destdir', 'cache_prefix', 'nocheck', 'want_spec', 'line'
)

#                      (kv, destdir, nocheck, want_spec, line)
def fetch_cached_source(kw, destdir, cache_prefix, nocheck=False, line=''):
    relpath = _get_required_attr(kw, 'relpath', line)
    uri = os.path.join(cache_prefix, relpath)
    return fetch_uri_source(kw, destdir, uri, nocheck, line)


#                   (kv, destdir, nocheck, want_spec, line)
def fetch_uri_source(kw, destdir, uri, nocheck=False, line=''):
    # TODO: handle different checksum types HERE
    sha1sum = kw.get('sha1sum') #if nocheck else _get_required_attr(kw, 'sha1sum', line)

    # NOTE: does not respect Content-Disposition
    outfile = os.path.join(destdir, os.path.basename(uri))

    download_uri(uri, outfile)

    if sha1sum: # or not nocheck:
        check_file_checksum(outfile, sha1sum, nocheck)

    return outfile


def check_file_checksum(path, sha1sum, nocheck):
    efmt = "sha1sum mismatch for '%s':\n    expected: %s\n    got:   %s"
    got_sha1sum = sha1sum_file(path)
    if sha1sum != got_sha1sum:
        msg = efmt % (path, sha1sum, got_sha1sum)
        if nocheck:
            log.warning(msg + "\n    (ignored)")
        else:
            raise Error(msg)


def sha1sum_file(path):
    return checksum_file(path, "sha1sum")

_checksum_len_by_type = dict(md5sum=32, sha1sum=40, sha256sum=64, sha512sum=128)
_checksum_type_by_len = dict( (v,k) for k,v in _checksum_len_by_type.items() )

def checksum_file(path, checksum_type):
    checksum_len = _checksum_len_by_type[checksum_type]
    output = subprocess.check_output(checksum_type, stdin=open(path))
    m = re.match(r'([0-9a-f]{%d}) ' % checksum_len, output)
    if not m:
        print("output was: %s" % output)
        raise RuntimeError("got garbage output back from '%d'" % checksum_type)
    return m.group(1)


def parse_meta_url(line):
    """
    fields:
        type={git|github|vdt-upstream|uri}
        repo=owner/reponame  # type=github only
        path=name/version/filename  # vdt-upstream only
        # url for uri type
        # filename for uri type (might not match uri suffix)
        # auto filename for uri type respecting content-disposition
        sha1sum=file_checksum  # mainly for non-git, but can use for git also
        # or checksum=file_checksum checksum_type=sha1sum, etc,
        # which we might use internally anyway
        url=git_clone_url
        name=tarball_package_name
        tag=refname
        hash=commit_sha1
        spec=rpm/NAME.spec
    """

    kv = [ entry.split("=", 1) for entry in line.split() ]
    args = [ a[0] for a in filter((lambda t: len(t) == 1), kv) ]
    kv = dict( filter((lambda t: len(t) == 2), kv) )

    len(args) <= 2 # OR ELSE
    # AUTO-URI [CHECKSUM]
    #
    # AUTO-URI:
    #
    # /path/to...          -> file:// uri
    # owner/repo.git       -> github (*)
    # path/to/file.ext     -> cached
    # proto://.../repo.git -> git (*)
    # proto://...          -> uri

    # (*) but note other items are required for git
    #     maybe: "OWNER/REPO.git TAG COMMIT_HASH" at a minimum

    # now can use this for ALL source lines... mmm...

    return args, kv


def process_meta_url(line, destdir, nocheck, want_spec=True):
    """
    Process a serialized URL spec.  Should be of the format:
     type=git url=https://github.com/opensciencegrid/cvmfs-config-osg.git name=cvmfs-config-osg tag=0.1 hash=e2b54cd1b94c9e3eaee079490c9d85f193c52249
    'name' can be derived from the URL if the last component in the URL is of the form 'NAME.git'
    OR
     type=github repo=opensciencegrid/cvmfs-config-osg tag=0.1 hash=e2b54cd1b94c9e3eaee079490c9d85f193c52249
    'name' can be taken from the repo if not specified.

    If nocheck is True, hashes do not have to match.
    """

    args,kv = parse_meta_url(line)

    # TODO: get cache_prefix properly
    ops = FetchOptions(destdir=destdir, cache_prefix=C.WEB_CACHE_PREFIX,
                       nocheck=nocheck, want_spec=want_spec, line=line)

    handlers = dict(
        git    = fetch_git_source,
        github = fetch_github_source,
        cached = fetch_cached_source,
        uri    = fetch_uri_source,
    )
    meta_type = kv.get('type')
    if meta_type in handlers:
        fetch_source = handlers[meta_type]
        sha, tar_gz, spec = fetch_source(*args, ops=ops, **kv)
        files = list(filter(None, (tar_gz, spec)))
        return files

    contents = {}
    for entry in line.split():
        info = entry.split("=", 1)
        if len(info) > 1:
            contents[info[0].strip()] = info[1].strip()

    name = contents.get("name")
    tag_type = contents.get("type", "")
    if tag_type == "github":
        repo = contents.get("repo")
        if not repo:
            raise Error("No repo specified: %s" % line)
        m = re.match(r"([^\s/]+)/([^\s/]+?)(?:.git)?$", repo)
        if not m:
            raise Error("Repo syntax must be owner/project: %s" % line)
        owner, project = m.group(1, 2)
        git_url = "https://github.com/%s/%s" % (owner, project)
        if not name:
            name = project

    elif tag_type == "git":
        git_url = contents.get('url')
        if not git_url:
            raise Error("No git URL provided: %s" % line)
        if not name:
            basename = os.path.basename(git_url)
            if basename[-4:] == '.git':
                name = basename[:-4]
            else:
                raise Error("No package name specified: %s" % line)

    else:
        raise Error("Only 'git'- and 'github'-type sources are understood: %s" % line)

    git_hash = contents.get("hash")
    if not git_hash:
        raise Error("git hash not provided.")

    tag, tarball = contents.get("tag"), contents.get("tarball")
    if not tag:
        msg = "tag not specified: %s" % line
        if nocheck:
            log.warning(msg + "\n    (ignored)")
        else:
            raise Error(msg)
    if tarball:
        if not tarball[-7:] == ".tar.gz":
            raise Error("tarball must end with .tar.gz: %s" % line)
        dest_file = tarball[:-3]  # the .tar file; we'll gzip it ourselves
    elif tag:
        tarball_version = tag
        if re.match("v[0-9]+", tarball_version):
            tarball_version = tarball_version[1:]
        # Chop off the release tag (if there is one). This is something like
        # the "-1" in "3.3-1".  Dashes are not allowed in RPM version numbers
        # so chop off the first dash and everything afterward.
        dashidx = tarball_version.find('-')
        if dashidx != -1:
            tarball_version = tarball_version[:dashidx]
        dest_file = "%s-%s.tar" % (name, tarball_version)  # the .tar file; we'll gzip it ourselves
    else:
        raise Error("No package tag or tarball specified: %s" % line)

    log.info("Checking out git repo for %s.", name)

    destdir = os.path.abspath(destdir)
    checkout_dir = tempfile.mkdtemp(prefix=dest_file, dir=destdir)
    try:
        rc = utils.unchecked_call(["git", "clone", git_url, checkout_dir])
        if rc:
            raise Error("`git clone %s %s` failed with exit code %d" % (git_url, checkout_dir, rc))

        orig_dir = os.getcwd()
        os.chdir(checkout_dir)
        try:
            if tag:
                output, rc = utils.sbacktick(["git", "show-ref", tag])
                if rc:
                    raise Error("Repository %s does not contain a tag named %s." % (git_url, tag))
                sha1 = output.split()[0]
                if sha1 != git_hash and deref_git_sha(sha1) != deref_git_sha(git_hash):
                    msg = "Hash mismatch for %s tag %s\n    expected: %s\n    actual:   %s" % \
                          (git_url, tag, git_hash, sha1)
                    if nocheck:
                        log.warning(msg + "\n    (ignored)")
                        git_hash = sha1
                    else:
                        raise Error(msg)
            # Check out the branch/tag/ref we're building; we're looking for the
            # spec file in the working dir, not the archive. Can't check it out
            # directly in git clone (with "--branch") b/c on el6 git versions
            # that doesn't work on non-branches (e.g. tags).
            rc = utils.unchecked_call(["git", "checkout", "-q", git_hash])
            if rc:
                raise Error("Unable to check out %s for some reason." % git_hash)

            full_dest_file = os.path.join(destdir, dest_file)
            prefix = dest_file[:-4]  # the tar file minus the .tar
            rc = utils.unchecked_call(["git", "archive", "--format=tar", "--prefix=%s/" % prefix, git_hash, "--output=%s" % full_dest_file])
            if rc:
                raise Error("Failed to create an archive of hash %s" % git_hash)

            # git-archive can't create .tar.gz files on git 1.7.1 (SLF 6) so gzip the tar file ourselves
            # gzip -n will keep hashes of gzips of identical tarballs identical (by
            # omitting timestamp information)
            rc = utils.unchecked_call(["gzip", "-fn", full_dest_file])
            if rc:
                raise Error("Failed to compress archive at %s" % full_dest_file)

            files = [full_dest_file + ".gz"]

            spec_file = os.path.join(checkout_dir, "rpm", name + ".spec")
            log.info("Looking for spec file %s in repo", spec_file)
            if os.path.exists(spec_file):
                log.info("Found spec file")
                shutil.copy(spec_file, destdir)
                files.append(spec_file)
            else:
                log.info("Did not find spec file")
        finally:
            os.chdir(orig_dir)
    finally:
        shutil.rmtree(checkout_dir)

    return files

def deref_git_sha(sha):
    output, rc = utils.sbacktick(["git", "rev-parse", sha + "^{}"])
    if rc:
        raise Error("Git failed to parse rev: '%s'" % sha)
    return output

def process_dot_source(cache_prefix, sfilename, destdir, nocheck):
    """Read a .source file, fetch any files mentioned in it from the
    cache.

    """
    utils.safe_makedirs(destdir)
    downloaded = []
    with open(sfilename, 'r') as sfile:
        for lineno, line in enumerate(sfile):
            line = line.strip()
            if line.startswith('#'):
                continue
            if line == '':
                continue
            if len(line.split()) > 1:
                filenames = process_meta_url(line, destdir, nocheck)
                downloaded.extend(filenames)
                continue
            elif line.startswith('/'):
                uri = "file://" + line
                log.warning(
                    "An absolute path has been given in %s line %d. "
                    "It is recommended to use only paths relative to %s"
                    "in your source files.", sfilename, lineno+1,
                    cache_prefix)
            elif not re.match(r'/|\w+://', line): # relative path
                uri = os.path.join(cache_prefix, line)
            else:
                uri = line

            log.info('Retrieving ' + uri)
            try:
                handle = urllib.request.urlopen(uri)
            except urllib.error.URLError as err:
                raise Error("Unable to download %s\n%s" % (uri, str(err)))
            filename = os.path.join(destdir, os.path.basename(line))
            try:
                with open(filename, 'wb') as desthandle:
                    desthandle.write(handle.read())
            except EnvironmentError as err:
                raise Error("Unable to save downloaded file to %s\n%s" % (filename, str(err)))
            downloaded.append(filename)

    return downloaded
# end of process_dot_source()


def full_extract(unpacked_dir, archives_downloaded, destdir):
    """Extract downloaded archives plus archives inside downloaded SRPMs"""
    archives_in_srpm = []
    if os.path.isdir(unpacked_dir):
        for fname in glob.glob(os.path.join(unpacked_dir, '*')):
            if os.path.isfile(fname):
                archives_in_srpm.append(os.path.abspath(fname))
    utils.safe_makedirs(destdir)
    utils.pushd(destdir)
    for fname in archives_downloaded + archives_in_srpm:
        log.info("Extracting " + fname)
        utils.super_unpack(fname)
    utils.popd()
    log.info('Extracted files to ' + destdir)


def extract_srpms(srpms_downloaded, destdir):
    """Extract SRPMs to destdir"""
    abs_srpms_downloaded = [os.path.abspath(x) for x in srpms_downloaded]
    utils.safe_makedirs(destdir)
    utils.pushd(destdir)
    for srpm in abs_srpms_downloaded:
        log.info("Unpacking SRPM " + srpm)
        utils.super_unpack(srpm)
    utils.popd()


def copy_with_filter(files_list, destdir):
    """Copy files in files_list to destdir, skipping backup files and
    directories.

    """
    for fname in files_list:
        base = os.path.basename(fname)
        if (base in [C.WD_RESULTS,
                     C.WD_PREBUILD,
                     C.WD_UNPACKED,
                     C.WD_UNPACKED_TARBALL] or
                base.endswith('~') or
                os.path.isdir(fname)):
            log.debug("Skipping file " + fname)
        else:
            log.debug("Copying file " + fname)
            shutil.copy(fname, destdir)


def fetch(package_dir,
          destdir=None,
          cache_prefix=C.WEB_CACHE_PREFIX,
          unpacked_dir=None,
          want_full_extract=False,
          unpacked_tarball_dir=None,
          nocheck=False):
    """Process *.source files in upstream/ directory, downloading upstream
    sources mentioned in them from the software cache. Unpack SRPMs if
    there are any. Override upstream files with those in the osg/
    directory. Return the path to the downloaded spec file. 

    """
    if destdir is None:
        destdir = package_dir
    if unpacked_dir is None:
        unpacked_dir = destdir
    if unpacked_tarball_dir is None:
        unpacked_tarball_dir = destdir

    abs_package_dir = os.path.abspath(package_dir)

    upstream_dir = os.path.join(abs_package_dir, 'upstream')
    osg_dir = os.path.join(abs_package_dir, 'osg')

    # Process upstream/*.source files
    dot_sources = glob.glob(os.path.join(upstream_dir, '*.source'))
    downloaded = []
    for src in dot_sources:
        log.debug('Processing .source file %s', src)
        for fname in process_dot_source(cache_prefix, src, destdir, nocheck):
            downloaded.append(os.path.abspath(fname))

    # Process downloaded SRPMs
    srpms = fnmatch.filter(downloaded, '*.src.rpm')
    if srpms:
        extract_srpms(srpms, unpacked_dir)
    if unpacked_dir != destdir:
        for f in glob.glob(os.path.join(unpacked_dir, '*')):
            log.debug('Copying unpacked file ' + f)
            shutil.copy(f, destdir)

    # Copy non *.source files in upstream
    other_sources = [x for x in glob.glob(os.path.join(upstream_dir, '*'))
                     if (not fnmatch.fnmatch(x, '*.source')
                         and os.path.isfile(x))]
    copy_with_filter(other_sources, destdir)

    # Extract any archives we downloaded plus any archives in the SRPM
    if want_full_extract:
        full_extract(unpacked_dir, downloaded, unpacked_tarball_dir)

    # Override downloaded files with what's in osg/
    copy_with_filter(glob.glob(os.path.join(osg_dir, '*')),
                     destdir)

    # Return list of spec files
    spec_glob = os.path.join(destdir, '*.spec')
    spec_filenames = glob.glob(spec_glob)
    if not spec_filenames:
        raise GlobNotFoundError(spec_glob)
    if len(spec_filenames) > 1:
        raise Error("Multiple spec files found: " + ", ".join(spec_filenames))

    return spec_filenames[0]
# end of fetch


if __name__ == '__main__':
    nocheck = False
    package_dirs = []
    if len(sys.argv) < 2:
        package_dirs = ["."]
    else:
        for arg in sys.argv[1:]:
            if arg == "--nocheck":
                nocheck = True
            else:
                package_dirs.append(arg)
    try:
        for package_dir in package_dirs:
            fetch(os.path.abspath(package_dir), nocheck=nocheck)
    except Error as e:
        print("Error: %s" % e, file=sys.stderr)
        sys.exit(1)
