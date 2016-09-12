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
CCFLAGS =
LINT=verilator
LINTFLAGS =  --lint-only  -Wall -Wno-fatal -Wno-DECLFILENAME


all: top.sim core.sim


top.sim: $(TOP_TB_SRC) $(TOP_SRC)
	$(CC) $(CCFLAGS) -o top.sim $(TOP_TB_SRC) $(TOP_SRC)


core.sim: $(CORE_TB_SRC) $(CORE_SRC)
	$(CC) $(CCFLAGS) -o core.sim $(CORE_SRC) $(CORE_TB_SRC)

lint:  $(TOP_SRC)
	$(LINT) $(LINTFLAGS) $(TOP_SRC)

sim-core: core.sim
	./core.sim


sim-top: top.sim
	./top.sim


help:
	@echo "Supported targets:"
	@echo "------------------"
	@echo "all:      Build all simulation targets."
	@echo "top.sim:  Build the top simulation target."
	@echo "core.sim  Build the top simulation target."
	@echo "lint:     Run lint on the source."
	@echo "sim-top:  Run top level simulation."
	@echo "sim-core: Run core level simulation."
	@echo "clean:    Remove build targets."

clean:
	rm -f core.sim
	rm -f top.sim

#===================================================================
# EOF Makefile
#===================================================================
