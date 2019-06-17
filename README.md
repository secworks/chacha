chacha
========

Verilog 2001 implementation of the ChaCha stream cipher.

## Status ##
The core is completed and has been implemented and used in several FPGA
designs. The core is for example used as the CSPRNG/DRBG part of the
random number generator (RNG) in the [Cryptech
HSM](https://cryptech.is/).


## Introduction ##
This core implements the [ChaCha stream cipher
(pdf)](https://cr.yp.to/chacha/chacha-20080128.pdf) By Daniel
J. Bernstein (DJB).


## Functionality ##
This core implements ChaCha with support for 128 and 256 bit keys. The
number of rounds can be set from two to 32 rounds in steps of two. The
default number of rounds is eight.

The core contains an internal 64-bit block counter that is automatically
updated for each data block.

There is a [reference model in a separate
repository](https://github.com/secworks/chacha_testvectors) used to
generate and document test vectors. There is also a functional model in
this repo under src/model/python.


## Branch for VHDL interoperability ##
There is a branch
[*vhdl_interop*](https://github.com/secworks/chacha/tree/vhdl_interop)
that changes the port name "next" in *chacha_core.v*. Next is a reserved
word in VHDL. If you are instantiating the core in a mixed language
environment use this branch. This branch will not be merged into
*master*, but will track changes to the *master* branch.


## Performance ##
The core has four separate quarterround modules, which means that
one round takes one cycle. The overhead latency cost when using the top
level wrapper is three, which means that with eight rounds the total
latency is 11 cycles. For ChaCha20 the latency is 23 cycles.


## Implementation ##
Implementation results using the Altera Quartus Prime 15.1 design tool.

### Cyclone IV E ###
- 4748 LEs
- 1940 registers
- 55 MHz


### Cyclone V GX ###
- 1939 ALMs for logic
- 1940 registers
- 60 MHz


Implementation results using Xilinx ISE 14.7.

### Xilinx Spartan-6 ###
- xc6slx75-3fgg676
- 3843 slice LUTs
- 1049 slices
- 1994 registers
- 83 MHz


### Xilinx Artix-7 ###
- xc7a200t-3fbg484
- 3837 slice LUTs
- 1076 slices
- 1949 registers
- 100 MHz
