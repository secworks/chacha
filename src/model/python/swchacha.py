#!/usr/bin/env python
# -*- coding: utf-8 -*-
#=======================================================================
#
# swchacha.py
# -----------
# Simple model of the ChaCha stream cipher. Used as a reference for
# the HW implementation. The code follows the structure of the
# HW implementation as much as possible.
#
# 
# Copyright (c) 2013 Secworks Sweden AB
# Author: Joachim Strömbergson
# 
# Redistribution and use in source and binary forms, with or 
# without modification, are permitted provided that the following 
# conditions are met: 
# 
# 1. Redistributions of source code must retain the above copyright 
#    notice, this list of conditions and the following disclaimer. 
# 
# 2. Redistributions in binary form must reproduce the above copyright 
#    notice, this list of conditions and the following disclaimer in 
#    the documentation and/or other materials provided with the 
#    distribution. 
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#=======================================================================

#-------------------------------------------------------------------
# Python module imports.
#-------------------------------------------------------------------
import sys


#-------------------------------------------------------------------
# Constants.
#-------------------------------------------------------------------
TAU   = [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574]
SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]


#-------------------------------------------------------------------
# ChaCha()
#-------------------------------------------------------------------
class ChaCha():
    
    #---------------------------------------------------------------
    # __init()
    #
    # Given the key, iv initializes the state of the cipher.
    # The number of rounds used can be set. By default 8 rounds
    # are used. Accepts a list of either 16 or 32 bytes as key.
    # Accepts a list of 8 bytes as IV.
    #---------------------------------------------------------------
    def __init__(self, key, iv, rounds = 8, verbose = False):
        self.state = [0] * 16
        self.rounds = rounds
        self.verbose = verbose
        self.set_key_iv(key, iv)


    #---------------------------------------------------------------
    # set_key_iv()
    # 
    # Set key and iv. Basically reinitialize the cipher.
    # This also resets the block counter.
    #---------------------------------------------------------------
    def set_key_iv(self, key, iv):
        keyword0 = self._b2w(key[0:4])
        keyword1 = self._b2w(key[4:8])
        keyword2 = self._b2w(key[8:12])
        keyword3 = self._b2w(key[12:16])
        
        if len(key) == 16:
            self.state[0]  = TAU[0]
            self.state[1]  = TAU[1]
            self.state[2]  = TAU[2]
            self.state[3]  = TAU[3]
            self.state[4]  = keyword0
            self.state[5]  = keyword1
            self.state[6]  = keyword2
            self.state[7]  = keyword3
            self.state[8]  = keyword0
            self.state[9]  = keyword1
            self.state[10] = keyword2
            self.state[11] = keyword3

        elif len(key) == 32:
            keyword4 = self._b2w(key[16:19])
            keyword5 = self._b2w(key[20:23])
            keyword6 = self._b2w(key[24:27])
            keyword7 = self._b2w(key[28:31])
            self.state[0]  = SIGMA[0]
            self.state[1]  = SIGMA[1]
            self.state[2]  = SIGMA[2]
            self.state[3]  = SIGMA[3]
            self.state[4]  = keyword0
            self.state[5]  = keyword1
            self.state[6]  = keyword2
            self.state[7]  = keyword3
            self.state[8]  = keyword4
            self.state[9]  = keyword5
            self.state[10] = keyword6
            self.state[11] = keyword7
        else:
            print "Key length of %d bits, is not supported." % (len(key) * 8)

        # Common state init for both key lengths.
        self.block_counter = [0, 0]
        self.state[12] = self.block_counter[0]
        self.state[13] = self.block_counter[1]
        self.state[14] = self._b2w(iv[0:4])
        self.state[15] = self._b2w(iv[4:8])


    #---------------------------------------------------------------
    # next()
    #
    # Encyp/decrypt the next block. This also updates the
    # internal state and increases the block counter.
    #---------------------------------------------------------------
    def next(self, data_in):
        # Copy the current internal state to the temporary state x.
        self.x = self.state[:]
        
        # Update the internal state by performing
        # (rounds / 2) double rounds.
        for i in range(self.rounds / 2):
            self._doubleround()

        # Update the internal state by adding the elements
        # of the temporary state to the internal state.
        self.state = [((self.state[i] + self.x[i]) & 0xffffffff) for i in range(16)]
        bytestate = []
        for i in self.state:
            bytestate += self._w2b(i)
        
        # Create the data out words.
        data_out = [data_in[i] ^ bytestate[i] for i in range(64)]

        # Update the block counter.
        self._inc_counter()
        
        return data_out


    #---------------------------------------------------------------
    # _doubleround()
    #
    # Perform the two complete rounds that comprises the
    # double round.
    #---------------------------------------------------------------
    def _doubleround(self):
        self._quarterround(0, 4,  8, 12)
        self._quarterround(1, 5,  9, 13)
        self._quarterround(2, 6, 10, 14)
        self._quarterround(3, 7, 11, 15)
        
        self._quarterround(0, 5, 10, 15)
        self._quarterround(1, 6, 11, 12)
        self._quarterround(2, 7,  8, 13)
        self._quarterround(3, 4,  9, 14)

            
    #---------------------------------------------------------------
    #  _quarterround()
    #
    # Updates four elements in the state vector x given by
    # their indices.
    #---------------------------------------------------------------
    def _quarterround(self, ai, bi, ci, di):
        # Extract four elemenst from x using the qi tuple.
        a, b, c, d = self.x[ai], self.x[bi], self.x[ci], self.x[di]

        if self.verbose:
            print "Indata to quarterround:"
            print "X state indices:", ai, bi, ci, di
            print "a = 0x%08x, b = 0x%08x, c = 0x%08x, d = 0x%08x" % (a, b, c, d)
            print
            
        a0 = (a + b) & 0xffffffff
        d0 = d ^ a0
        d1 = ((d0 << 16) + (d0 >> 16)) & 0xffffffff
        c0 = (c + d1) & 0xffffffff
        b0 = b ^ c0
        b1 = ((b0 << 12) + (b0 >> 20)) & 0xffffffff
        a1 = (a0 + b1) & 0xffffffff
        d2 = d1 ^ a1
        d3 = ((d2 << 8) + (d2 >> 24)) & 0xffffffff
        c1 = (c0 + d3) & 0xffffffff 
        b2 = b1 ^ c1
        b3 = ((b2 << 7) + (b2 >> 25)) & 0xffffffff 

        if self.verbose:
            print "Intermediate values:"
            print "a0 = 0x%08x, a1 = 0x%08x" % (a0, a1)
            print "b0 = 0x%08x, b1 = 0x%08x, b2 = 0x%08x, b3 = 0x%08x" % (b0, b1, b2, b3)
            print "c0 = 0x%08x, c1 = 0x%08x" % (c0, c1)
            print "d0 = 0x%08x, d1 = 0x%08x, d2 = 0x%08x, d3 = 0x%08x" % (d0, d1, d2, d3)
            print
        
        a_prim = a1
        b_prim = b3
        c_prim = c1
        d_prim = d3

        if self.verbose:
            print "Outdata from quarterround:"
            print "a_prim = 0x%08x, b_prim = 0x%08x, c_prim = 0x%08x, d_prim = 0x%08x" %\
                  (a_prim, b_prim, c_prim, d_prim)
        
        # Update the four elemenst in x using the qi tuple.
        self.x[ai], self.x[bi] = a_prim, b_prim
        self.x[ci], self.x[di] = c_prim, d_prim


    #---------------------------------------------------------------
    # _inc_counter()
    #
    # Increase the 64 bit block counter.
    #---------------------------------------------------------------
    def _inc_counter(self):
        self.block_counter[0] += 1 & 0xffffffff
        if not (self.block_counter[0] % 0xffffffff):
            self.block_counter[1] += 1 & 0xffffffff


    #---------------------------------------------------------------
    # _b2w()
    #
    # Given a list of four bytes returns the little endian
    # 32 bit word representation of the bytes.
    #---------------------------------------------------------------
    def _b2w(self, bytes):
        return (bytes[0] + (bytes[1] << 8)
                + (bytes[2] << 16) + (bytes[3] << 24)) & 0xffffffff


    #---------------------------------------------------------------
    # _w2b()
    #
    # Given a 32-bit word returns a list of set of four bytes
    # that is the little endian byte representation of the word.
    #---------------------------------------------------------------
    def _w2b(self, word):
        return [(word & 0x000000ff), ((word & 0x0000ff00) >> 8),
                ((word & 0x00ff0000) >> 16), ((word & 0xff000000) >> 24)]


#-------------------------------------------------------------------
# print_block()
#
# Print a given block (list) of bytes ordered in
# rows of eight bytes.
#-------------------------------------------------------------------
def print_block(block):
    for i in range(0, len(block), 8):
        print "0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x" %\
              (block[i], block[i+1], block[i+2], block[i+3],
               block[i+4], block[i+5], block[i+6], block[i+7])


#-------------------------------------------------------------------
# check_block()
#
# Compare the result block with the expected block and print
# if the result for the given test case was correct or not.
#-------------------------------------------------------------------
def check_block(result, expected, test_case):
    if result == expected:
        print "SUCCESS: %s was correct." % test_case
    else:
        print "ERROR: %s was not correct." % test_case

    
#-------------------------------------------------------------------
# main()
#
# If executed tests the ChaCha class using known test vectors.
#-------------------------------------------------------------------
def main():
    print "Testing the ChaCha Python model."
    
    # Code that tests the quarterround directly.
    # my_cipher = ChaCha(my_key, my_iv, verbose=True)
    # my_cipher.x = [0x11223344, 0x55555555] * 8
    # my_cipher._quarterround(0, 2, 4, 6)
    # my_cipher._quarterround(1, 3, 5, 7)

    # Testing with TC1.
    # All zero inputs, 128 bit key.
#    print "TC1: All zero inputs. 128 bit key, 8 rounds."
#    my_key1 = [0x00000000, 0x00000000, 0x00000000, 0x00000000]
#    my_iv1  = [0x00000000, 0x00000000]
#    my_block = [0x00000000] * 16
#    my_cipher = ChaCha(my_key1, my_iv1, verbose=False)
#    my_result1 = my_cipher.next(my_block)
#    print_block(my_result1)
#    print ""

    # Testing with TC2.
    # Single bit set in key. IV all zero. 128 bit key.
    print "TC2: One bit in key set. IV all zeros. 128 bit key, 8 rounds."
    key2 = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    iv2  = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    expected2 = [0, 1, 2, 3]
    block2 = [0x00] * 64
    cipher2 = ChaCha(key2, iv2, verbose=False)
    result2 = cipher2.next(block2)
    print_block(result2)
    check_block(result2, expected2, "TC2")
    print ""
    
    # Testing with TC8
    print "TC8: Random inputs. 128 bit key, 8 rounds."
    my_key8 = [0xc4, 0x6e, 0xc1, 0xb1, 0x8c, 0xe8, 0xa8, 0x78,
               0x72, 0x5a, 0x37, 0xe7, 0x80, 0xdf, 0xb7, 0x35]
    my_iv8  = [0x1a, 0xda, 0x31, 0xd5, 0xcf, 0x68, 0x82, 0x21]
    my_block = [0x00] * 64
    my_cipher = ChaCha(my_key8, my_iv8, verbose=False)
    my_result8 = my_cipher.next(my_block)
    print_block(my_result8)
        

#-------------------------------------------------------------------
# __name__
# Python thingy which allows the file to be run standalone as
# well as parsed from within a Python interpreter.
#-------------------------------------------------------------------
if __name__=="__main__": 
    # Run the main function.
    sys.exit(main())

#=======================================================================
# EOF swchacha.py
#=======================================================================
