swchacha
========

Verilog 2001 implementation of the ChaCha stream cipher.


The current implementation contains a chacha core with wide
interfaces. The core should be wrapped in a top module that provides a
proper core API.

The core does not contain any internal block counter, but assumes that
the user/host supplies the counter and updates the counter
appropriately.

The main purpose of this implementation is as a proof of concept and as
a comparison of hardware complexity and performance in comparison with
Salsa20.

