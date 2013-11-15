import re
import os

from datetime import datetime
from osgbuild.error import ClientCertError
from osgbuild import utils

class ClientCert(object):
    __slots__ = ['filename', 'first_commonname', 'enddate']

    def __init__(self, filename):
        self.filename = str(filename)

        if not os.path.exists(self.filename):
            raise ClientCertError(self.filename, "file not found")

        self.do_openssl_lookup()
        self.check_expired()

    def do_openssl_lookup(self):
        cmd = ["openssl", "x509",
                    "-in", self.filename,
                    "-noout",
                    "-subject", "-nameopt", "multiline",
                    "-enddate"]
        output = utils.checked_backtick(cmd, clocale=True)

        self.enddate = self.extract_enddate(output)
        self.first_commonname = self.extract_first_commonname(output)

    def extract_enddate(self, output):
        enddate_match = re.search(r"""(?xms)
                ^ notAfter=([^\n]+) $""", output)
        enddate = None
        if enddate_match:
            # Want to match something like "Nov 15 09:49:34 2013 GMT"
            try:
                enddate = datetime.strptime(enddate_match.group(1), "%b %d %H:%M:%S %Y %Z")
            except ValueError:
                pass
        if not enddate:
            raise ClientCertError(self.filename, "cannot determine expiration date")
        return enddate

    def extract_first_commonname(self, output):
        # Get the first commonName using the negative lookbehind assertion to make
        # sure we're capturing the right commonName if there are multiple.
        # Note that the commonName is indented since we're using multiline
        # output format.
        cn_match = re.search(r"""(?xms)
            (?!<commonName)
            ^ \s* commonName \s* = \s* ([^\n]+) $""", output)
        if not cn_match:
            raise ClientCertError(self.filename, "cannot determine commonName")
        return cn_match.group(1)

    def check_expired(self):
        if datetime.utcnow() > self.enddate:
            raise ClientCertError(self.filename, "cert expired")


