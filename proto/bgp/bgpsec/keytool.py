#!/usr/bin/env python
#
# Copyright (C) 2014 Dragon Research Labs ("DRL")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL DRL BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Key management tool for revised version of Sparta's BGPSEC implementation.
"""

import os
import sys
import argparse
import subprocess


default_openssl_binary  = os.getenv("BGPSEC_OPENSSL_BINARY",  "openssl")
default_public_key_dir  = os.getenv("BGPSEC_PUBLIC_KEY_DIR",  "/usr/share/bird/bgpsec-keys")
default_private_key_dir = os.getenv("BGPSEC_PRIVATE_KEY_DIR", "/usr/share/bird/bgpsec-private-keys")


class OpenSSLPipeline(object):
  """
  String together one or more OpenSSL commands in a pipeline, return
  stdout of the final command.  Callable object rather than function
  so we can instantiate it as a closure over the program arguments.
  """

  allowed_keywords = set(["input"])

  def __init__(self, args):
    self.args = args

  def __call__(self, *argses, **kwargs):
    assert all(kw in self.allowed_keywords for kw in kwargs)
    procs = []
    for args in argses:
      procs.append(subprocess.Popen((self.args.openssl_binary,) + args,
                                    stdout = subprocess.PIPE,
                                    stdin = procs[-1].stdout if procs else subprocess.PIPE))
    if "input" in kwargs:
      procs[0].stdin.write(kwargs["input"])
    procs[0].stdin.close()
    output = procs[-1].stdout.read()
    for i, proc in enumerate(procs):
      if proc.wait() != 0:
        raise subprocess.CalledProcessError(proc.returncode, argses[i][0])
    return output
# class OpenSSLPipeline(object):


def public_filename(args, asn, skihex):
  """
  Figure out what the filename for a key should be, and create the
  containing directory if it doesn't already exist.
  """

  for n in xrange(args.max_ski_collisions):
    fn = "%s/%s.%s.%s.key" % (args.public_key_dir, asn, skihex, n)
    if args.skip_collision_check or not os.path.exists(fn):
      break
  else:
    sys.exit("Too many SKI collisions for ASN %s SKI %s" % (asn, skihex))
  dn = os.path.dirname(fn)
  if not os.path.isdir(dn):
    if args.verbose:
      print "Creating directory", dn
    os.makedirs(dn)
  return fn
# def public_filename(args, asn, skihex):


def generate(args):
  """
  Generate an EC keypair, store in .key files named using the key's
  SKI value to generate the filenames.
  """

  # We go through some silly gymnastics using the old OpenSSL ecparam
  # command instead of using the newer OpenSSL genpkey command,
  # because we have to force the key into the required namedCurve form
  # instead of explicitCurve.  OpenSSL itself doesn't much care, but
  # since the SKI is defined as the SHA1 hash of the binary key value,
  # using the wrong key encoding yields the wrong SKI value.

  openssl = OpenSSLPipeline(args)
  pemkey = openssl(("ecparam", "-name", "prime256v1"),
                   ("ecparam", "-param_enc", "named_curve", "-genkey"))
  pemkey = pemkey.splitlines(True)
  pemkey = "".join(pemkey[pemkey.index("-----BEGIN EC PRIVATE KEY-----\n"):])
  skihex = openssl(("pkey", "-outform", "DER", "-pubout"),
                   ("dgst", "-sha1", "-hex"),
                   input = pemkey)
  skihex = skihex.split()[-1].upper()
  if args.printski:
    print skihex
  fn = public_filename(args, args.asns[0], skihex)
  if args.verbose:
    print "Writing", fn
  openssl(("pkey", "-outform", "DER", "-out", fn, "-pubout"), input = pemkey)
  for asn in args.asns[1:]:
    ln = public_filename(args, asn, skihex)
    if args.verbose:
      print "Linking", ln
    os.link(fn, ln)
  os.umask(077)
  fn = "%s/%s.%s.key" % (args.private_key_dir, args.asns[0], skihex)
  if args.verbose:
    print "Writing", fn
  openssl(("pkey", "-outform", "DER", "-out", fn), input = pemkey)
  for asn in args.asns[1:]:
    ln = "%s/%s.%s.key" % (args.private_key_dir, asn, skihex)
    if args.verbose:
      print "Linking", ln
    os.link(fn, ln)
# def generate(args):


def hashdir(args):
  """
  Extract router keys from certificates in an RPKI certificate tree,
  store as .key files using each key's SKI value to generate the
  corresponding filename.
  """

  openssl = OpenSSLPipeline(args)
  for root, dirs, files in os.walk(args.cert_dir):
    for fn in files:
      if fn.endswith(".cer"):
        fn = os.path.join(root, fn)
        text = openssl(("x509", "-inform", "DER", "-noout", "-text", "-in", fn))
        if "Public Key Algorithm: id-ecPublicKey" not in text or "ASN1 OID: prime256v1" not in text:
          continue
        if args.verbose:
          print "Examining", fn
        skihex = text[text.index("X509v3 Subject Key Identifier:"):].splitlines()[1].strip().replace(":", "").upper()
        if args.paranoia:
          checkski = openssl(("x509", "-inform", "DER", "-noout", "-pubkey", "-in", fn),
                             ("pkey", "-pubin", "-outform", "DER"),
                             ("dgst", "-sha1", "-hex"))
          checkski = checkski.split()[-1].upper()
          if skihex != checkski:
            sys.stderr.write("SKI %s in certificate %s does not match calculated SKI %s\n" % (skihex, fn, checkski))
        asns = []
        b = text.index("Autonomous System Numbers:")
        e = text.index("\n\n", b)
        for line in text[b:e].splitlines()[1:]:
          b, _, e = line.strip().partition("-")
          if e == "":
            asns.append(int(b))
          else:
            asns.extend(xrange(int(b), int(e) + 1))
        outfn = public_filename(args, asns[0], skihex)
        if args.verbose:
          print "Writing", outfn
        openssl(("x509", "-inform", "DER", "-noout", "-pubkey", "-in", fn),
                ("pkey", "-pubin", "-outform", "DER", "-out", outfn))
        for asn in asns[1:]:
          ln = public_filename(args, asn, skihex)
          if args.verbose:
            print "Linking", ln
          os.link(outfn, ln)
# def hashdir(args):


def main():
  parser = argparse.ArgumentParser(description = __doc__)
  parser.add_argument("--openssl-binary",
                      default = default_openssl_binary,
                      help = "Path to EC-capable OpenSSL binary")
  parser.add_argument("--public-key-dir",
                      default = default_public_key_dir,
                      help = "directory to which we save parsed router keys")
  parser.add_argument("--private-key-dir",
                      default = default_private_key_dir,
                      help = "directory to which we save generated private keys")
  parser.add_argument("--verbose",
                      action = "store_true",
                      help = "whistle while you work")
  parser.add_argument("--printski",
                      action = "store_true",
                      help = "print out the SKI value")
  parser.add_argument("--paranoia",
                      action = "store_true",
                      help = "perform paranoid checks")
  parser.add_argument("--max-ski-collisions",
                      type = int,
                      default = 3,
                      help = "maximum number of SKI collisions to allow when writing public keys")
  parser.add_argument("--skip-collision-check",
                      action = "store_true",
                      help = "don't check for SKI collisions")
  subparsers = parser.add_subparsers(title = "Commands",
                                     metavar = "")
  subparser = subparsers.add_parser("generate",
                                    description = generate.__doc__,
                                    help = "generate new keypair")
  subparser.set_defaults(func = generate)
  subparser.add_argument("--router-id",
                         type = int)
  subparser.add_argument("asns",
                         nargs = "+",
                         type = int)
  subparser = subparsers.add_parser("hashdir",
                                    description = hashdir.__doc__,
                                    help = "hash directory of certs")
  subparser.set_defaults(func = hashdir)
  subparser.add_argument("cert_dir")
  args = parser.parse_args()
  return args.func(args)
# def main():


if __name__ == "__main__":
  sys.exit(main())
