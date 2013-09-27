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
    def __init__(self, key, iv, rounds = 8, verbose = False):
        self.key = key
        self.iv = iv
        self.rounds = rounds
        self.x = [0] * 16
        self.block_counter = [0, 0]
        self.verbose = verbose
        
        if len(key) == 4:
            # 128 bit key
            pass
        
        else:
            # 256 bit key
            pass
        

    #---------------------------------------------------------------
    #---------------------------------------------------------------
    def next(data_in):
        data_out = [data_in[i] ^ self.x[i] for i in range(16)]
        return data_out


    #---------------------------------------------------------------
    # _doubleround()
    #---------------------------------------------------------------
    def _doubleround():
        for i in range((self.rounds / 2)):
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


    # --------------------------------------------------------------
    # _inc_counter()
    # Increase the 64 bit block counter.
    # --------------------------------------------------------------
    def _inc_counter(self):
        self.block_counter[0] += 1 & 0xffffffff
        if not (self.block_counter[0] % 0xffffffff):
            self.block_counter[1] += 1 & 0xffffffff

    
#-------------------------------------------------------------------
# main()
#
# Parse arguments.
#-------------------------------------------------------------------
def main():
    print "Testing the ChaCha Python model."

    my_key = [0x00000000, 0x11111111, 0x22222222, 0x33333333,
              0x44444444, 0x55555555, 0x66666666, 0x77777777]
    my_iv  = [0x00000000, 0x00000001]
    
    my_cipher = ChaCha(my_key, my_iv, verbose=True)
    my_cipher.x = [0x11223344, 0x55555555] * 8
    my_cipher._quarterround(0, 2, 4, 6)
    my_cipher._quarterround(1, 3, 5, 7)


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
