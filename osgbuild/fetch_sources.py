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


def _required(item, key):
    if item is None:
        raise Error("No '%s' specified" % key)

def _mk_prefix(name, tag, tarball):
    if tarball:
        if not tarball.endswith('.tar.gz'):
            raise Error("tarball must end with .tar.gz: '%s'" % tarball)
        prefix = tarball[:-len('.tar.gz')]
    else:
        tarball_version = re.match(r'(?:v(?=\d))?([^-]+)', tag).group(1)
        prefix = "%s-%s" % (name, tarball_version)
    return prefix

def fetch_github_source(repo, tag, hash=None, ops=None, **kw):
    m = re.match(r"([^\s/]+)/([^\s/]+?)(?:.git)?$", repo)
    if not m:
        raise Error("'repo' syntax for type=github must be owner/project")
    url = "https://github.com/" + repo
    return fetch_git_source(url, tag, hash, ops=ops, **kw)

def nvl(arg, default):
    return default if arg is None else arg

def fetch_git_source(url, tag, hash=None, ops=None,
        name=None, spec=None, tarball=None):
    name = name or re.sub(r'\.git$', '', os.path.basename(url))
    ops.nocheck or _required(hash, 'hash')
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
        raise Error("Unable to save downloaded file to %s\n%s"
                                           % (output_path, err))


# common fetch options not found in .source line
FetchOptions = collections.namedtuple('FetchOptions',
    ['destdir', 'cache_prefix', 'nocheck', 'want_spec']
)

def fetch_cached_source(relpath, sha1sum=None, ops=None):
    uri = os.path.join(ops.cache_prefix, relpath)
    return fetch_uri_source(uri, sha1sum, ops=ops)


def fetch_uri_source(uri, sha1sum=None, ops=None, filename=None):
    if uri.startswith('/'):
        uri = "file://" + uri
        log.warning("Absolute path names in .source files break the 4th wall")

    outfile = os.path.join(ops.destdir, os.path.basename(filename or uri))
    download_uri(uri, outfile)

    if sha1sum: # or not ops.nocheck:
        check_file_checksum(outfile, sha1sum, ops.nocheck)

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
    output = subprocess.check_output("sha1sum", stdin=open(path))
    m = re.match(r'([0-9a-f]{40}) ', output)
    if not m:
        print("output was: %s" % output)
        raise Error("got garbage output back from sha1sum: '%s'" % output)
    return m.group(1)

def dual_filter(cond, seq):
    pos,neg = [],[]
    for x in seq:
        (pos if cond(x) else neg).append(x)
    return pos,neg

def kvmatch(arg):
    # return (key,val) for "key=val", else return (None, arg)
    return re.search(r'^(?:(\w+)=)?(.*)', arg).groups()

def parse_meta_url(line):
    kv, args = dual_filter((lambda t: t[0]), map(kvmatch, line.split()))
    return list(zip(*args))[1], dict(kv)

def get_auto_uri_type(*args, **kw):
    if not args:
        raise Error("No type specified and no default arg provided")
    if re.search(r'^\w+://', args[0]):
        return 'git' if args[0].endswith('.git') else 'uri'
    elif args[0].startswith('/'):
        return 'uri'
    else:
        return 'github' if args[0].endswith('.git') else 'cached'


def process_meta_url(line, ops):
    """
    Process URL spec: [args...] [field=value...]

    fields names:

      type:     {git|github|uri|cached}
      url:      git clone url (type=git)
      name:     repo name if different from url basename (type=git, optional)
      tag:      git tag or ref to archive (type=git/github)
      hash:     git commit hash (type=git/github, optional if nocheck=True)
      repo:     owner/repo (type=github)
      tarball:  archive name if not name-tag.tar.gz (type=git/github, optional)
      spec:     path rpm spec, if not rpm/name.spec (type=git/github, optional)
      uri:      uri for file to download (type=uri)
      filename: outfile if different than uri basename (type=uri, optional)
      sha1sum:  chksum of downloaded file (type=uri, optional if nocheck=True)
      relpath:  upstream cache relative path (type=cached)


    default args may be provided to automatically determine type:

        owner/repo.git       -> github
        proto://.../repo.git -> git
        pkg/version/file.ext -> cached
        proto://...          -> uri
        /abs/path/to/file    -> uri (file://)


    unnamed args will be interpreted for each type:

        github: repo tag  [hash]
        git:    url  tag  [hash]

        cached: relpath [sha1sum]
        uri:    uri     [sha1sum]
    """

    args,kv = parse_meta_url(line)

    handlers = dict(
        git    = fetch_git_source,
        github = fetch_github_source,
        cached = fetch_cached_source,
        uri    = fetch_uri_source,
    )
    meta_type = kv.get('type') or get_auto_uri_type(*args, **kv)
    if meta_type in handlers:
        fetch_source = handlers[meta_type]
        sha, tar_gz, spec = fetch_source(*args, ops=ops, **kv)
        files = list(filter(None, (tar_gz, spec)))
        return files
    else:
        raise Error("Unrecognized type '%s'" % meta_type)


def deref_git_sha(sha):
    output, rc = utils.sbacktick(["git", "rev-parse", sha + "^{}"])
    if rc:
        raise Error("Git failed to parse rev: '%s'" % sha)
    return output

def process_dot_source(cache_prefix, sfilename, destdir, nocheck):
    """Read a .source file, fetch any sources specified in it."""
    ops = FetchOptions(destdir=destdir, cache_prefix=cache_prefix,
                       nocheck=nocheck, want_spec=True)

    utils.safe_makedirs(destdir)
    filenames = []
    for line in open(sfilename):
        line = re.sub(r'(^|\s)#.*', '', line).strip()
        if line:
            try:
                filenames += process_meta_url(line, ops)
            except Error as e:
                log.error("Error processing source line: '%s'" % line)
                raise

    return filenames


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
