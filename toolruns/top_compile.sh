#!/bin/sh
# Compile command for the core.
iverilog -o test_top ../src/tb/tb_chacha.v ../src/rtl/chacha.v ../src/rtl/chacha_core.v ../src/rtl/chacha_qr.v


