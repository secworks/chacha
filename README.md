swchacha
========

Verilog 2001 implementation of the ChaCha stream cipher.

## Purpose ###
The main purpose of this implementation is as a proof of concept and as
a comparison of hardware complexity and performance in comparison with
Salsa20 and other ciphers.


## Functionality ##
This core implements ChaCha with support for 128 and 256 bit keys. The
number of rounds can be set from two to 32 rounds in steps of two. The
default number of rounds is eight.

The core contains an internal 64-bit block counter that is automatically
updated for each data block.


## Performance ##
Each quarterround takes one cycle which means that the mininum latency
will be 4*rounds. When the core is functionally correct we will add two
more version with 2 and 4 parallel quarterrounds respectively. The four
quarterounds version will achieve 1 cycle/round.


## Status ##
(2013-10-06)
- Added TC1 from chacha_testvectors. Testing shows that the Python model
generates correct result, but is intra word-big endian, not little
endian. We need to flip the words around.



(2013-10-04)
- The reference model has been moved to a separate project created just
  to generate and document ChaCha test vectors. See:
  https://github.com/secworks/chacha_testvectors


(2013-10-03)
- There is now also a c reference model that is intended to generate
test vectors for different combinations of keys, iv, blocks and rounds.


(2013-09-26)
- Debugging of the core is ongoing with quarterround at the focus.
- The core goes through the motions of processing blocks.
- There is a testbench for the top level the top seems to work ok.
- There is a Python model being developed in src/model.
- Quarterround in the Python model works. Used to debug the RTL.


(Older stuff)
- The current implementation consists of a ChaCha core with (very) wide
  data interfaces. 

- There is also a top level wrapper, chacha.v that provides a memory
  like 32-bit API. Note that with

- The core is currently not completed. The datapath and control is
  basically completed but needs to be debugged. The initial version of
  the testbench for the core is done but the core is not yet connected.

- The top level wrapper is functionally completed, but not yet
  debugged. There is no testbench.


## Notes ##

