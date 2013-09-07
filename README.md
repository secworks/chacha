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
will be 4*rounds.


## Status ##
The current implementation consists of a ChaCha core with (very) wide
data interfaces.

There is also a top level wrapper, chacha.v that provides a
memory like 32-bit API. Note that with

The core is currently not completed. The datapath and control is
basically completed but needs to be debugged. The initial version of the
testbench for the core is done but the core is not yet connected.

The top level wrapper is functionally completed, but not yet
debugged. The wrapper does not yet have a testbench.


## Notes ##
The core does not contain any internal block counter, but assumes that
the user/host supplies the counter and updates the counter
appropriately.

