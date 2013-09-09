//======================================================================
//
// tb_chacha_core.v
// -----------------
// Testbench for the Chacha stream cipher core.
//
//
// Copyright (c) 2013, Secworks Sweden AB
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or 
// without modification, are permitted provided that the following 
// conditions are met: 
// 
// 1. Redistributions of source code must retain the above copyright 
//    notice, this list of conditions and the following disclaimer. 
// 
// 2. Redistributions in binary form must reproduce the above copyright 
//    notice, this list of conditions and the following disclaimer in 
//    the documentation and/or other materials provided with the 
//    distribution. 
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

//------------------------------------------------------------------
// Simulator directives.
//------------------------------------------------------------------
`timescale 1ns/10ps

module tb_chacha_core();
  
  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter CLK_HALF_PERIOD = 2;

  
  //----------------------------------------------------------------
  // Register and Wire declarations.
  //----------------------------------------------------------------
  // Cycle counter.
  reg [31 : 0] cycle_ctr;

  // Clock and reset.
  reg tb_clk;
  reg tb_reset_n;

  // Wires needded to connect the core.
  reg           tb_core_init;
  reg           tb_core_next;
  reg [255 : 0] tb_core_key;
  reg           tb_core_keylen;
  reg [4 : 0]   tb_core_rounds;
  reg [63 : 0]  tb_core_iv;
  reg [511 : 0] tb_core_data_in;
  wire [511 : 0] tb_core_data_out;
  
  
  //----------------------------------------------------------------
  // chacha_core device under test.
  //----------------------------------------------------------------
  chacha_core dut(
                   // Clock and reset.
                   .clk(tb_clk),
                   .reset_n(tb_reset_n),
                
                   // Control.
                   .init(tb_core_init),
                   .next(tb_core_next),

                   // Parameters.
                   .key(tb_core_key),
                   .key_length(tb_core_keylength),
                   .iv(tb_core_iv),
                   .rounds(tb_core_rounds),
                   
                   // Data input.
                   .data_in(tb_core_data_in),
                   
                   // Status output.
                   .ready(tb_core_ready),
                    
                   // Data out with valid signal.
                   .data_out(tb_core_data_out),
                   .data_out_valid(tb_core_data_out_valid)
                  );
  

  //----------------------------------------------------------------
  // clk_gen
  // Clock generator process. 
  //----------------------------------------------------------------
  always 
    begin : clk_gen
      #CLK_HALF_PERIOD tb_clk = !tb_clk;
    end // clk_gen

  
  //--------------------------------------------------------------------
  // dut_monitor
  // Monitor for observing the inputs and outputs to the dut.
  // Includes the cycle counter.
  //--------------------------------------------------------------------
  always @ (posedge tb_clk)
    begin : dut_monitor
      cycle_ctr = cycle_ctr + 1;

      $display("cycle = %8x:", cycle_ctr);
      // $display("v0_reg = %016x, v1_reg = %016x", dut.v0_reg, dut.v1_reg);
      // $display("v2_reg = %016x, v3_reg = %016x", dut.v2_reg, dut.v3_reg);
      // $display("loop_ctr = %02x, dp_state = %02x, fsm_state = %02x", 
      // dut.loop_ctr_reg, dut.dp_state_reg, dut.chacha_ctrl_reg);
      // $display("");
    end // dut_monitor


  //----------------------------------------------------------------
  // dump_inputs
  // Dump the internal CHACHA state to std out.
  //----------------------------------------------------------------
  // task dump_inputs();
  //   begin
  //     $display("Inputs:");
  //     $display("init = %b, compress = %b, finalize = %b", 
  //              tb_initalize, tb_compress, tb_finalize);
  //     $display("reset = %b, c = %02x, d = %02x, mi = %08x", 
  //              tb_reset_n, tb_c, tb_d, tb_mi);
  //     $display("");
  //   end
  // endtask // dump_inputs


  //----------------------------------------------------------------
  // dump_outputs
  // Dump the outputs from the Chacha to std out.
  //----------------------------------------------------------------
  // task dump_outputs();
  //   begin
  //     $display("Outputs:");
  //     $display("ready = %d", tb_ready);
  //     $display("chacha_word = 0x%016x, valid = %d", tb_chacha_word, tb_chacha_word_valid);
  //     $display("");
  //   end
  // endtask // dump_inputs


  //----------------------------------------------------------------
  // dump_state
  // Dump the internal CHACHA state to std out.
  //----------------------------------------------------------------
  // task dump_state();
  //   begin
  //     $display("Internal state:");
  //     $display("v0_reg = %016x, v1_reg = %016x", dut.v0_reg, dut.v1_reg);
  //     $display("v2_reg = %016x, v3_reg = %016x", dut.v2_reg, dut.v3_reg);
  //     $display("mi_reg = %016x", dut.mi_reg);
  //     $display("loop_ctr = %02x, dp_state = %02x, fsm_state = %02x", 
  //              dut.loop_ctr_reg, dut.dp_state_reg, dut.chacha_ctrl_reg);
  //     $display("");
  //   end
  // endtask // dump_state

  
  //----------------------------------------------------------------
  // chacha_core_test
  // The main test functionality. 
  //----------------------------------------------------------------
  initial
    begin : chacha_core_test
      $display("   -- Testbench for chacha_core started --");
      
      // Set clock, reset and DUT input signals to 
      // defined values at simulation start.
      cycle_ctr    = 0;
      tb_clk       = 0;
      tb_reset_n   = 0;
      tb_reset_n = 0;

      // dump_state();
      
      // Wait ten clock cycles and release reset.
      #(20 * CLK_HALF_PERIOD);
      @(negedge tb_clk)
      tb_reset_n = 1;
      // dump_state();
      
      // Dump the state to check reset.
      #(4 * CLK_HALF_PERIOD);
      // dump_state();
      // dump_outputs();

      
      // Finish in style.
      $display("chacha_core simulation done.");
      $finish;
    end // chacha_core_test
  
endmodule // tb_chacha_core

//======================================================================
// EOF tb_chacha_core.v
//======================================================================
