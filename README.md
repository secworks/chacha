[![build-openlane-sky130](https://github.com/secworks/chacha/actions/workflows/ci.yml/badge.svg?branch=master&event=push)](https://github.com/secworks/chacha/actions/workflows/ci.yml)

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

## FuseSoC
This core is supported by the
[FuseSoC](https://github.com/olofk/fusesoc) core package manager and
build system. Some quick  FuseSoC instructions:

Install FuseSoC
~~~
pip install fusesoc
~~~

Create and enter a new workspace
~~~
mkdir workspace && cd workspace
~~~

Register chacha as a library in the workspace
~~~
fusesoc library add chacha /path/to/chacha
~~~
...if repo is available locally or...
...to get the upstream repo
~~~
fusesoc library add chacha https://github.com/secworks/chacha
~~~

Run tb_chacha testbench
~~~
fusesoc run --target=tb_chacha secworks:crypto:chacha
~~~

Run with modelsim instead of default tool (icarus)
~~~
fusesoc run --target=tb_chacha --tool=modelsim secworks:crypto:chacha
~~~

List all targets
~~~
fusesoc core show secworks:crypto:chacha
~~~

## Implementation results##

### Intel Cyclone IV E ###
- Tool: Altera Quartus Prime 15.1
- LEs:  4748
- Regs: 1940
- RAM:     0
- Fmax: 55 MHz


### Intel Cyclone V GX ###
- Tool: Altera Quartus Prime 15.1
- ALMs: 1939
- Regs: 1940
- Ram:     0
- Fmax: 60 MHz


### Microchip IGLOO2 ###
- Tool:   Libero v 12.4
- Device: M2GL150TS-FCV484
- LUTs:   4190
- SLEs:   2028
- BRAMs:  2
- Fmax:   88.4 MHz


### Microchip PolarFire ###
- Tool:   Libero v 12.4
- Device: MPF500TS-FCG784I
- LUTs:   4190
- SLEs:   1992
- BRAMs:  3
- Fmax:   94.4 MHz


### Xilinx Spartan-6 ###
- Tool:   Xilinx ISE 14.7
- Device: xc6slx75-3fgg676
- LUTs:   3843
- Slices: 1049
- Regs:   1994
- BRAM:      0
- Fmax:   83 MHz


### Xilinx Artix-7 ###
- Tool:   Xilinx ISE 14.7
- Device: xc7a200t-3fbg484
- LUTs:   3837
- Slices: 1076
- Regs:   1949
- BRAM:      0
- Fmax:   100 MHz
