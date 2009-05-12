#!/usr/bin/python
"""Implementation of Steve Gibson's "Perfect Paper Passwords" (PPP)

Generates sequences of pseudo-random one-time passwords based on a
specified passphrase or a 64-character sequence key.

For further information see <http://www.grc.com/ppp.htm>

Copyright (C) 2009 Padraig Kitterick <p.kitterick@psych.york.ac.uk>
All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
"""
import sys
from optparse import OptionParser, OptionGroup
from hashlib import sha256

import aes

SHA256_DIGEST_SIZE = 64
WORD_SIZE = 8 # 1-byte word occupies a maximum of 8 bits
WORD_COUNT = 128/WORD_SIZE # 16 x 1-byte (8-bit) words = 128 bits
MAX_WORD_VALUE = (2 ** WORD_SIZE) - 1
MAX_INT = (2 ** 128) - 1 # maximum possible passcode number
CHARACTER_ARRAY = "23456789!@#%+=:?abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPRSTUVWXYZ"

def hex2bytes(hexstr):
    if len(hexstr) is not SHA256_DIGEST_SIZE:
        return None
    
    bytes = []
    for i in xrange(SHA256_DIGEST_SIZE/2):
        try:
            bytes.append(int(hexstr[i*2:(i*2)+2], base=16))
        except ValueError:
            return None
    return bytes

def pack128(n):
    if not 0 <= n <= MAX_INT:
        raise IndexError('integer %r cannot be packed into 128 bits.' % hex(n))
    
    words = []
    for i in range(WORD_COUNT):
        word = n & MAX_WORD_VALUE
        words.append(int(word))
        n >>= WORD_SIZE
    
    return words

def unpack128(words):
    n = 0
    for i, num in enumerate(words):
        word = num
        word = word << WORD_SIZE * i
        n = n | word
    
    return n

def create_passcodes(key, chars, startnum, numpass, passlen):
    num_chars = len(chars)
    passcode = [" "] * passlen
    codes = []
    
    a = aes.AES()
    for i in range(startnum, startnum+numpass):
        val = pack128(i)
        ciph = a.encrypt(val, key, a.keySize["SIZE_256"])
        ciph_val = unpack128(ciph)
        
        for j in range(passlen):
            passcode[j] = chars[ciph_val % num_chars]
            ciph_val = ciph_val / num_chars
        
        codes.append(''.join(passcode))
    return codes

def display_codes(codes, page=None, linelen=7):
    if len(codes) < linelen:
        linelen = len(codes)
    
    header = "PPP Passcard"
    line = '-' * ((4*(linelen+1)) + linelen)
    
    print header,
    if page:
        print ' ' * (len(line)-len(header)-2-len(str(page))),
        print page,
    print
    print line
    
    colh = ord('A')
    print "     ",
    for i in range(linelen):
        print " %s  " % chr(colh),
        colh += 1
    print
    
    col = 0
    row = 1
    print "%2d: " % row,
    for code in codes:
        if col == linelen:
            col = 0
            print
            row += 1
            print "%2d: " % row,
        print code,
        col += 1
    print
    print line

if __name__ == '__main__':
    usage = "usage: %prog [options] [-k KEY|-p PHRASE]"
    version = "%prog 0.1a"
    parser = OptionParser(usage=usage, version=version)
    
    group = OptionGroup(parser, "Required Options",
                        "One, and only one, of the following must be specified.")
    group.add_option("-k", dest="key",
                      help="a %d-character hex sequence" % SHA256_DIGEST_SIZE, metavar="KEY")
    group.add_option("-p", dest="passphrase", metavar="PHRASE",
                      help="passphrase with which to create a KEY")
    parser.add_option_group(group)
    
    
    parser.add_option("-n", dest="numpass", default=70, metavar="NUM", type='int',
                      help="generate NUM passcodes (default: %default)")
    parser.add_option("-s", dest="startnum", default=0, metavar="N", type='int',
                      help="start at passcode N (default: %default)")
    parser.add_option("--page", dest="page", metavar="P", type='int',
                      help="display page P of NUM passcodes. Alternative to specifying a starting passcode number")
    parser.add_option("-l", dest="passlen", default=4, metavar="LEN", type='int',
                      help="generated passcodes of length LEN (default: %default)")
    parser.add_option("-c", dest="chars", default=CHARACTER_ARRAY, metavar="ARRAY",
                      help="ARRAY of characters to create passcodes with. Default: %default")
    parser.add_option("-v", dest="verbose", action="store_true",
                      help="Print information about the key, alphabet, and codes.")
    
    (options, args) = parser.parse_args()
    
    # We need a key or a passphrase
    if (options.key and options.passphrase) or (not options.key and not options.passphrase):
        parser.error("Please specify either -k or -p."
                     "\n\nSee --help for usage information.")
    
    if options.page and options.startnum is not 0:
        parser.error("Please specify either -s or --page but not both.");
    
    key = None
    key_bytes = []
    if options.passphrase:
        key = sha256(options.passphrase).hexdigest()
        key_bytes = hex2bytes(key)
    else:
        key_bytes = hex2bytes(options.key)
        if key_bytes:
            key = options.key
        
        if not key:
            sys.exit("Supplied key was not a valid %d character hex key." % SHA256_DIGEST_SIZE)
    
    if options.chars:
        chars = options.chars
    else:
        chars = CHARACTER_ARRAY
    
    numpass = options.numpass
    if options.page:
        startnum = (options.page-1) * numpass
    else:
        startnum = options.startnum
    passlen = options.passlen
    
    chars = list(chars)
    chars.sort()
    
    if options.verbose:
        print "Sequence key: %s" % key
        print "Using alphabet: %s" % ''.join(chars)
        print "Passcode length: %d" % passlen
    
    codes = create_passcodes(key_bytes, chars, startnum, numpass, passlen)
    
    if numpass == 1:
        print codes[0]
    else:
        display_codes(codes, options.page)
