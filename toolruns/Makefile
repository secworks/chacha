#===================================================================
#
# Makefile
# --------
# Makefile for building core and top simulation.
#
#
# (c) 2013 Joachim Strombergson
#
#===================================================================

CORE_SRC=../src/rtl/chacha_core.v ../src/rtl/chacha_qr.v
CORE_TB_SRC=../src/tb/tb_chacha_core.v

TOP_SRC=../src/rtl/chacha.v $(CORE_SRC)
TOP_TB_SRC=../src/tb/tb_chacha.v

CC=iverilog


all: top.sim core.sim


top.sim: $(TOP_TB_SRC) $(TOP_SRC)
	$(CC) -o top.sim $(TOP_TB_SRC) $(TOP_SRC)


core.sim: $(CORE_TB_SRC) $(CORE_SRC)
	$(CC) -o core.sim $(CORE_SRC) $(CORE_TB_SRC)


sim-core: core.sim
	./core.sim


sim-top: top.sim
	./top.sim


help:
	@echo "Supported targets:"
	@echo "------------------"
	@echo "all:      Build all simulation targets."
	@echo "top:      Build the top simulation target."
	@echo "core:     Build the top simulation target."
	@echo "sim-top:  Run top level simulation."
	@echo "sim-core: Run core level simulation."
	@echo "debug:    Print the internal varibles."

clean:
	rm -f core.sim
	rm -f top.sim

#===================================================================
# EOF Makefile
#===================================================================
