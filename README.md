swchacha
========

Verilog 2001 implementation of the ChaCha stream cipher.

## Purpose ###
The main purpose of this implementation is as a proof of concept and as
a comparison of hardware complexity and performance in comparison with
Salsa20.

## Functionality ##
This core implements ChaCha with support for 128 and 256 bit keys. The
number of rounds can be set from 1 to 15 rounds, with a default of 8
rounds.


## Performance ##
Each quarterround takes one cycle which means that the mininum latency
will be 4xrounds.


## Status ##
The current implementation consists of a ChaCha core with (very) wide
interfaces. The core should be wrapped in a top module that provides a
proper core API. There will be a top wrapper with a 32-bit interface as
well as a testbench.


## Notes ##
The core does not contain any internal block counter, but assumes that
the user/host supplies the counter and updates the counter
appropriately.

