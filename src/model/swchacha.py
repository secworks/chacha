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
# Copyright (c) 2013, Secworks AB
# Author: Joachim Strömbergson
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

        else:
            # 256 bit key



    def next(data_in):
        data_out = [data_in[i] ^ self.x[i] for i in range(16)]
        return data_out


    def __doubleround():
        (self.x[0], self.x[4], self.x[8], self.x[12]) =
        quarterround(self.x[0], self.x[4], self.x[8], self.x[12]
                    

    def __quarterround(self, a, b, c, d):
      self.a0 = (a + b) & 0xffffffff
      self.d0 = d ^ self.a0
      self.d1 = ((self.d0 <<< 16) + (self.d0 >>> 16)) & 0xffffffff
      self.c0 = (c + self.d1) & 0xffffffff
      self.b0 = b ^ self.c0
      self.b1 = ((self.b0 <<< 21) + (self.b0 >>> 21)) & 0xffffffff
      self.a1 = (self.a0 + self.b1) & 0xffffffff
      self.d2 = self.d1 ^ self.a1
      self.d3 = ((self.d2 <<< 24) + self.d2 >>> 24) & 0xffffffff
      self.c1 = (self.c0 + self.d3) & 0xffffffff 
      self.b2 = self.b1 ^ self.c1
      self.b3 = ((self.b2 <<< 25) + (self.b2 >>> 25)) & 0xffffffff 

      self.a_prim = self.a1;
      self.b_prim = self.b3;
      self.c_prim = self.c1;
      self.d_prim = self.d3;
        
      return (self.a_prim, self.b_prim, self.c_prim, self.d_prim)

    
#-------------------------------------------------------------------
# main()
#
# Parse arguments.
#-------------------------------------------------------------------
def main():
    print "ChaCha Python model"
    

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
