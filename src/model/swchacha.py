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
            self._quarterround((0, 4,  8, 12))
            self._quarterround((1, 5,  9, 13))
            self._quarterround((2, 6, 10, 14))
            self._quarterround((3, 7, 11, 15))
            
            self._quarterround((0, 5, 10, 15))
            self._quarterround((1, 6, 11, 12))
            self._quarterround((2, 7,  8, 13))
            self._quarterround((3, 4,  9, 14))

            
    #---------------------------------------------------------------
    #---------------------------------------------------------------
    def _quarterround(self, qi):
        # Extract four elemenst from x using the qi tuple.
        self.a, self.b = self.x[qi[0]], self.x[qi[1]]
        self.c, self.d = self.x[qi[2]], self.x[qi[3]]

        self.a0 = (a + b) & 0xffffffff
        self.d0 = d ^ self.a0
        self.d1 = ((self.d0 << 16) + (self.d0 >> 16)) & 0xffffffff
        self.c0 = (c + self.d1) & 0xffffffff
        self.b0 = b ^ self.c0
        self.b1 = ((self.b0 << 21) + (self.b0 >> 21)) & 0xffffffff
        self.a1 = (self.a0 + self.b1) & 0xffffffff
        self.d2 = self.d1 ^ self.a1
        self.d3 = ((self.d2 << 24) + self.d2 >> 24) & 0xffffffff
        self.c1 = (self.c0 + self.d3) & 0xffffffff 
        self.b2 = self.b1 ^ self.c1
        self.b3 = ((self.b2 << 25) + (self.b2 >> 25)) & 0xffffffff 
        
        self.a_prim = self.a1;
        self.b_prim = self.b3;
        self.c_prim = self.c1;
        self.d_prim = self.d3;
        
        # Update the four elemenst in x using the qi tuple.
        self.x[qi[0]], self.x[qi[1]] = self.a_prim, self.b_prim
        self.x[qi[2]], self.x[qi[3]] = self.c_prim, self.d_prim


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
    
    my_cipher = ChaCha(my_key, my_iv)
    

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
