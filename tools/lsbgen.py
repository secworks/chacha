#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#=======================================================================
#
# lsbgen.py
# ---------
# Given the length of a vector will calculate and print Verilog
# statements needed to extract a number of 32-bit words from
# the vector.
#
# The vector is assumed to be in the format [(n-1)..0] where n
# is the given number of bits. The vector is considered to
# be a byte representation of a sequence of bytes from left to
# right. This means that the first byte is in bits
# [(n-1)..(n-8)].
#
# Based on this 32-bit lsb words are extracted from left to
# right in increasing order. this means that LSB for word0
# is in bits [(n-1)..(n-8)] of the vector.
#
# Simple, isn't it? ;-)
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
# main()
#
# If executed tests the ChaCha class using known test vectors.
#-------------------------------------------------------------------
def main():
    vector_name = "state_reg"
    vector_bits = 512
    word_bits = 32
    word_name = "x"

    # Check that the given size is ok.
    if (vector_bits % word_bits != 0):
        print("Error: Vector with %d bits can not be evenly divided into %d-bit words." % (vector_bits, word_bits))
        return
    else:
        print("Creating %d words of size %d" )

    for i in range(int(vector_bits / word_bits)):
        b0max = (vector_bits - 1)  - i * word_bits
        b0min = (vector_bits - 8)  - i * word_bits
        b1max = (vector_bits - 9)  - i * word_bits
        b1min = (vector_bits - 16) - i * word_bits
        b2max = (vector_bits - 17) - i * word_bits
        b2min = (vector_bits - 24) - i * word_bits
        b3max = (vector_bits - 25) - i * word_bits
        b3min = (vector_bits - 32) - i * word_bits
        
        print("x%d_new = {%s[%d:%d], %s[%d:%d], %s[%d:%d], %s[%d:%d]}" %\
              (i, vector_name, b3max, b3min, vector_name, b2max, b2min,
               vector_name, b1max, b1min, vector_name, b0max, b0min))
                   

#-------------------------------------------------------------------
# __name__
# Python thingy which allows the file to be run standalone as
# well as parsed from within a Python interpreter.
#-------------------------------------------------------------------
if __name__=="__main__": 
    # Run the main function.
    sys.exit(main())

#=======================================================================
# EOF lsbgen.py
#=======================================================================
