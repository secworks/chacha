#!/bin/sh
# Compile command for the core.
iverilog -o test_core ../src/tb/tb_chacha_core.v ../src/rtl/chacha_core.v ../src/rtl/chacha_qr.v
