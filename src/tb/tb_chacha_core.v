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
  reg            tb_core_init;
  reg            tb_core_next;
  reg [255 : 0]  tb_core_key;
  reg            tb_core_keylen;
  reg [4 : 0]    tb_core_rounds;
  reg [63 : 0]   tb_core_iv;
  wire           tb_core_ready;
  reg [511 : 0]  tb_core_data_in;
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
                   .keylen(tb_core_keylen),
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
  // Monitor displaying information every cycle.
  // Includes the cycle counter.
  //--------------------------------------------------------------------
  always @ (posedge tb_clk)
    begin : dut_monitor
      cycle_ctr = cycle_ctr + 1;
      $display("cycle = %08x:", cycle_ctr);
      $display("");

      $display("chacha_ctrl_reg = %01x", dut.chacha_ctrl_reg);
      $display("qr_ctr_reg = %01x, dr_ctr_reg = %01x", dut.qr_ctr_reg, dut.dr_ctr_reg);
      $display("x0_reg   = %08x, x0_new   = %08x, x0_we  = %01x", dut.x0_reg, dut.x0_new, dut.x0_we);
      $display("x1_reg   = %08x, x1_new   = %08x, x1_we  = %01x", dut.x1_reg, dut.x1_new, dut.x1_we);
      $display("x2_reg   = %08x, x2_new   = %08x, x2_we  = %01x", dut.x2_reg, dut.x2_new, dut.x2_we);
      $display("x3_reg   = %08x, x3_new   = %08x, x3_we  = %01x", dut.x3_reg, dut.x3_new, dut.x3_we);
      $display("x4_reg   = %08x, x4_new   = %08x, x4_we  = %01x", dut.x4_reg, dut.x4_new, dut.x4_we);
      $display("x5_reg   = %08x, x5_new   = %08x, x5_we  = %01x", dut.x5_reg, dut.x5_new, dut.x5_we);
      $display("x6_reg   = %08x, x6_new   = %08x, x6_we  = %01x", dut.x6_reg, dut.x6_new, dut.x6_we);
      $display("x7_reg   = %08x, x7_new   = %08x, x7_we  = %01x", dut.x7_reg, dut.x7_new, dut.x7_we);
      $display("x8_reg   = %08x, x8_new   = %08x, x8_we  = %01x", dut.x8_reg, dut.x8_new, dut.x8_we);
      $display("x9_reg   = %08x, x9_new   = %08x, x9_we  = %01x", dut.x9_reg, dut.x9_new, dut.x9_we);
      $display("x10_reg  = %08x, x10_new  = %08x, x10_we = %01x", dut.x10_reg, dut.x10_new, dut.x10_we);
      $display("x11_reg  = %08x, x11_new  = %08x, x11_we = %01x", dut.x11_reg, dut.x11_new, dut.x11_we);
      $display("x12_reg  = %08x, x12_new  = %08x, x12_we = %01x", dut.x12_reg, dut.x12_new, dut.x12_we);
      $display("x13_reg  = %08x, x13_new  = %08x, x13_we = %01x", dut.x13_reg, dut.x13_new, dut.x13_we);
      $display("x14_reg  = %08x, x14_new  = %08x, x14_we = %01x", dut.x14_reg, dut.x14_new, dut.x14_we);
      $display("x15_reg  = %08x, x15_new  = %08x, x15_we = %01x", dut.x15_reg, dut.x15_new, dut.x15_we);
      $display("");

      $display("a      = %08x, b      = %08x, c      = %08x, d      = %08x", dut.quarterround.a, dut.quarterround.b, dut.quarterround.c, dut.quarterround.d);
      $display("a_prim = %08x, b_prim = %08x, c_prim = %08x, d_prim = %08x", dut.a_prim, dut.b_prim, dut.c_prim, dut.d_prim);
      $display("");
      
    end // dut_monitor


  //----------------------------------------------------------------
  // dump_state
  // Dump the internal CHACHA state to std out.
  //----------------------------------------------------------------
  task dump_state();
    begin
      $display("");
      $display("Internal state:");
      $display("---------------");
      $display("x0_reg  = %08x, x1_reg  = %08x", dut.x0_reg, dut.x1_reg);
      $display("x2_reg  = %08x, x3_reg  = %08x", dut.x2_reg, dut.x3_reg);
      $display("x4_reg  = %08x, x5_reg  = %08x", dut.x4_reg, dut.x5_reg);
      $display("x6_reg  = %08x, x7_reg  = %08x", dut.x6_reg, dut.x7_reg);
      $display("x8_reg  = %08x, x9_reg  = %08x", dut.x8_reg, dut.x9_reg);
      $display("x10_reg = %08x, x11_reg = %08x", dut.x10_reg, dut.x11_reg);
      $display("x12_reg = %08x, x13_reg = %08x", dut.x12_reg, dut.x13_reg);
      $display("x14_reg = %08x, x15_reg = %08x", dut.x14_reg, dut.x15_reg);
      $display("");
      $display("rounds_reg = %01x", dut.rounds_reg);
      $display("qr_ctr_reg = %01x, dr_ctr_reg  = %01x", dut.qr_ctr_reg, dut.dr_ctr_reg);
      $display("block0_ctr_reg = %08x, block1_ctr_reg = %08x", dut.block0_ctr_reg, dut.block1_ctr_reg);

      $display("");
      $display("chacha_ctrl_reg = %02x", dut.chacha_ctrl_reg);
      $display("");
      $display("data_in_reg = %064x", dut.data_in_reg);
      $display("data_out_valid_reg = %01x", dut.data_out_valid_reg);
      $display("");
      $display("a_prim = %08x, b_prim = %08x", dut.a_prim, dut.b_prim);
      $display("c_prim = %08x, d_prim = %08x", dut.c_prim, dut.d_prim);
      $display("");
    end
  endtask // dump_state


  //----------------------------------------------------------------
  // dump_inout
  // Dump the status for input and output ports.
  //----------------------------------------------------------------
  task dump_inout();
    begin
      $display("");
      $display("State for input and output ports:");
      $display("---------------------------------");


      $display("init       = %01x", dut.init);
      $display("next       = %01x", dut.next);
      $display("key_length = %01x", dut.key_length);
      $display("");

      $display("key = %032x", dut.key);
      $display("iv  = %016x", dut.iv);
      $display("");

      $display("ready          = %01x", dut.ready);
      $display("data_in        = %064x", dut.data_in);
      $display("data_out       = %064x", dut.data_out);
      $display("data_out_valid = %01x", dut.data_out_valid);
      $display("");
    end
  endtask // dump_inout

  
  //----------------------------------------------------------------
  // chacha_core_test
  // The main test functionality. 
  //----------------------------------------------------------------
  initial
    begin : chacha_core_test
      $display("   -- Testbench for chacha_core started --");
      
      // Set clock, reset and DUT input signals to 
      // defined values at simulation start.
      cycle_ctr         = 0;
      tb_clk            = 0;
      tb_reset_n        = 0;

      tb_core_key       = 256'h0000000000000001000000000000000100000000000000010000000000000001;
      tb_core_keylen    = 1;
      tb_core_rounds    = 5'b00100;
      tb_core_iv        = 64'h0000000000000001;
      tb_core_init      = 0;
      tb_core_next      = 0;
      tb_core_data_in   = 512'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000;
      
      
      $display("");
      $display("*** State at init.");
      dump_state();
      
      // Wait ten clock cycles and release reset.
      #(4 * CLK_HALF_PERIOD);
      @(negedge tb_clk)
      tb_reset_n = 1;
      
      #(2 * CLK_HALF_PERIOD);
      $display("");
      $display("*** State after release of reset.");
      //dump_state();
      // dump_inout();

      // Try and init the cipher.
      #(4 * CLK_HALF_PERIOD);
      $display("");
      $display("*** Initializing cipher to process first block.");
      tb_core_init = 1;
      // dump_inout();
      #(4 * CLK_HALF_PERIOD);
      tb_core_init = 0;
      // dump_inout();

      // Wait a while and observe what happens.
      #(1000 * CLK_HALF_PERIOD);
      dump_state();
      dump_inout();
      
      // Finish in style.
      $display("*** chacha_core simulation done.");
      $finish;
    end // chacha_core_test
  
endmodule // tb_chacha_core

//======================================================================
// EOF tb_chacha_core.v
//======================================================================
