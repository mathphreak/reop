import argparse
import reop
import sys
import os

parser = argparse.ArgumentParser(description="""reop - reasonable expectation
                                 of privacy""")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-D", action="store_const", const="DECRYPT", dest="verb",
                   help="""Decrypt a message-file.""")
group.add_argument("-E", action="store_const", const="ENCRYPT", dest="verb",
                   help="""Encrypt a message-file.""")
group.add_argument("-G", action="store_const", const="GENERATE", dest="verb",
                   help="""Generate a new key pair.""")
group.add_argument("-S", action="store_const", const="SIGN", dest="verb",
                   help="""Sign the message-file and create a
                   signature-file.""")
group.add_argument("-V", action="store_const", const="VERIFY", dest="verb",
                   help="""Verify that the signature in the signature-file
                   matches the contents of the message-file.""")
parser.add_argument("-1", help="""Encrypt messages using the deprecated version
                    1 format.""", action="store_true", dest="v1compat")
parser.add_argument("-b", help="""When encrypting, use a binary format for the
                    cipertext-file.""", action="store_true", dest="binary")
parser.add_argument("-e", help="""When signing, combine the message and its
                    signature in the signature-file.""", action="store_true",
                    dest="embedded")
parser.add_argument("-i", help="""During key pair generation, reop will tag the
                    key pair with the given identity.  When looking up key
                    pairs, reop will search for a pair tagged with the given
                    identity.""", action="store", dest="ident")
parser.add_argument("-m", help="""When signing, the file containing the message
                    to sign.  When verifying, the file containing the message
                    to verify.  When encrypting or decrypting, the
                    plaintext.""", action="store", dest="msgfile")
parser.add_argument("-n", help="""Do not ask for a passphrase during key
                    generation.""", action="store_true", dest="nopasswd")
parser.add_argument("-p", help="""A public key file produced by -G.""",
                    action="store", dest="pubkeyfile")
parser.add_argument("-q", help="""Quiet mode.  Suppress informational
                    output.""", action="store_true", dest="quiet")
parser.add_argument("-s", help="""A secret (private) key produced by -G.""",
                    action="store", dest="seckeyfile")
parser.add_argument("-x", help="""When signing or verifying, the
                    signature-file.  When encrypting, the ciphertext-file.""",
                    action="store", dest="xfile")
arguments = parser.parse_args()

reop.init()

verb = arguments.verb
v1compat = arguments.v1compat
binary = arguments.binary
embedded = arguments.embedded
ident = arguments.ident
msgfile = arguments.msgfile
pubkeyfile = arguments.pubkeyfile
quiet = arguments.quiet
seckeyfile = arguments.seckeyfile
xfile = arguments.xfile

# check files
if verb == "ENCRYPT" or verb == "DECRYPT":
    if msgfile is None:
        print "You must specify a message-file!"
        parser.print_usage()
        sys.exit(1)
    if xfile is None:
        if msgfile == "-":
            print "must specify encfile with - message"
            parser.print_usage()
            sys.exit(1)
        if False:  # TODO find out what /main.c:151 is doing and put it here
            print "path too long"
            sys.exit(1)
elif verb == "SIGN" or verb == "VERIFY":
    if xfile is None and msgfile == "-":
        print "must specify sigfile with - message"
        parser.print_usage()
        sys.exit(1)

# run stuff
if verb == "DECRYPT":
    reop.decrypt(pubkeyfile, seckeyfile, msgfile,
                 xfile)
elif verb == "ENCRYPT":
    if seckeyfile is not None and (pubkeyfile is None and ident is None):
        print "specify a public key or ident"
        parser.print_usage()
        sys.exit(1)
    if pubkeyfile is not None or ident is not None:
        if v1compat:
            reop.v1pubencrypt(pubkeyfile, ident, seckeyfile, msgfile, xfile,
                              binary)
        else:
            reop.pubencrypt(pubkeyfile, ident, seckeyfile, msgfile, xfile,
                            binary)
    else:
        reop.symencrypt(msgfile, xfile, binary)
elif verb == "GENERATE":
    if ident is None:
        try:
            ident = os.environ["USER"]
            if ident is None:
                ident = os.environ["ThisShouldntExist"]
                # TODO raise our own key error
        except KeyError as err:
            ident = "unknown"
    bad = (pubkeyfile is None and seckeyfile is not None)
    bad = bad or (pubkeyfile is not None and seckeyfile is None)
    if bad:
        print "specify a public and secret key"
        parser.print_usage()
        sys.exit(1)
    if pubkeyfile is None and seckeyfile is None:
        home = ""
        try:
            home = os.environ["HOME"]
        except StandardError as err:
            print "Can't find HOME"
            sys.exit(1)
        reop_dir = os.path.join(home, ".reop")
