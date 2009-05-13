#!/usr/bin/python
"""Implementation of Steve Gibson's "Perfect Paper Passwords" (PPP)

Generates sequences of pseudo-random one-time passwords based on a
specified passphrase or a 64-character sequence key.

For further information see <http://www.grc.com/ppp.htm>

Copyright (C) 2009 Padraig Kitterick <info@padraigkitterick.com>
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
import random
import aes

SHA256_DIGEST_SIZE = 64
WORD_SIZE = 8 # 1-byte word occupies a maximum of 8 bits
WORD_COUNT = 128/WORD_SIZE # 16 x 1-byte (8-bit) words = 128 bits
MAX_WORD_VALUE = (2 ** WORD_SIZE) - 1
MAX_INT = (2 ** 128) - 1 # maximum possible passcode number
CHARACTER_ARRAY = "23456789!@#%+=:?abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPRSTUVWXYZ"

def hex2bytes(hexstr):
    """Convert from a 64-character hex string to 32 8-bit integers"""
    if len(hexstr) is not SHA256_DIGEST_SIZE:
        return None
    
    bytes = []
    for i in xrange(SHA256_DIGEST_SIZE/2):
        try:
            bytes.append(int(hexstr[i*2:(i*2)+2], base=16))
        except ValueError:
            return None
    return bytes

def generate_random_key():
    """Generate a random key as a hex strings and byte list"""
    key_bytes = []
    for i in range(SHA256_DIGEST_SIZE/2):
        key_bytes.append(random.randrange(256))
    
    key = ''.join(["%02x" % x for x in key_bytes])
    
    return key, key_bytes

def pack128(n):
    """Format a 128-bit integer as a list of 16 bytes"""
    if not 0 <= n <= MAX_INT:
        raise IndexError('integer %r cannot be packed into 128 bits.' % hex(n))
    
    words = []
    for i in range(WORD_COUNT):
        word = n & MAX_WORD_VALUE
        words.append(int(word))
        n >>= WORD_SIZE
    
    return words

def unpack128(words):
    """Format a list of 16 bytes as a 128-bit integer"""
    n = 0
    for i, num in enumerate(words):
        word = num
        word = word << WORD_SIZE * i
        n = n | word
    
    return n

def create_passcodes(key, chars, startnum, numpass, passlen):
    """Generate passcodes from the provided key and integer counter."""
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
    """Format a list of codes in a pretty-printed table."""
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
