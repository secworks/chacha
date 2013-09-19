//======================================================================
//
// tb_chacha.v
// -----------
// Testbench for the Chacha top level wrapper.
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

module tb_chacha();
  
  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter CLK_HALF_PERIOD = 2;

  
  //----------------------------------------------------------------
  // Register and Wire declarations.
  //----------------------------------------------------------------
  // Cycle counter.
  reg [63 : 0] cycle_ctr;

  // Clock and reset.
  reg tb_clk;
  reg tb_reset_n;

  // Wires needded to connect the core.
  reg           tb_cs;
  reg           tb_write_read;
  reg  [7 : 0]  tb_address;
  reg  [31 : 0] tb_data_in;
  wire [31 : 0] tb_data_out;
  
  
  //----------------------------------------------------------------
  // Chacha device under test.
  //----------------------------------------------------------------
  chacha dut(
             // Clock and reset.
             .clk(tb_clk),
             .reset_n(tb_reset_n),
             
             // Control.
             .cs(tb_cs),
             .write_read(tb_write_read),
             
             // Data ports.
             .address(tb_address),
             .data_in(tb_data_in),
             .data_out(tb_data_out)
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
      $display("cycle = %016x:", cycle_ctr);
      $display("");
    end // dut_monitor


  //----------------------------------------------------------------
  // read_reg
  // Function that reads and display the value of 
  // a register in the dut.
  //----------------------------------------------------------------
  task read_reg(input [7 : 0] addr);
    begin
      tb_cs         = 1;
      tb_write_read = 0;
      tb_address    = addr;
      #(2 * CLK_HALF_PERIOD);
      $display("Read: addr 0x%02x = 0x%08x", addr, tb_data_out);
      #(2 * CLK_HALF_PERIOD);
      tb_cs = 0;
      tb_write_read = 0;
      tb_address    = 8'h00;
      tb_data_in    = 32'h00000000;
    end
  endtask // read_reg


  //----------------------------------------------------------------
  // write_reg
  // Function that writes to a register in the dut.
  //----------------------------------------------------------------
  task write_reg(input [7 : 0] addr, input [31 : 0] data);
    begin
      $display("write: addr 0x%02x = 0x%08x", addr, data);
      tb_cs         = 1;
      tb_write_read = 1;
      tb_address    = addr;
      tb_data_in    = data;
      #(2 * CLK_HALF_PERIOD);
      tb_cs         = 0;
      tb_write_read = 0;
      tb_address    = 8'h00;
      tb_data_in    = 32'h00000000;
    end
  endtask // write_reg


  //----------------------------------------------------------------
  // dump_state
  // Dump the internal CHACHA state to std out.
  //----------------------------------------------------------------
  task dump_state();
    begin
      $display("");
      $display("Internal state:");
      $display("---------------");
      $display("init_reg   = %01x", dut.init_reg);
      $display("next_reg   = %01x", dut.next_reg);
      $display("ready_reg  = %01x", dut.ready_reg);
      $display("keylen_reg = %01x", dut.keylen_reg);
      $display("rounds_reg = %01x", dut.rounds_reg);

      $display("key0_reg = %08x, key1_reg  = %08x, key2_reg = %08x, key3_reg  = %08x", dut.key0_reg, dut.key1_reg, dut.key2_reg, dut.key3_reg);
      $display("key4_reg = %08x, key5_reg  = %08x, key6_reg = %08x, key7_reg  = %08x", dut.key4_reg, dut.key5_reg, dut.key6_reg, dut.key7_reg);
      $display("");
      $display("iv0_reg = %08x, iv1_reg = %08x", dut.iv0_reg, dut.iv1_reg);
      $display("");
      $display("data_in0_reg  = %08x, data_in1_reg   = %08x, data_in2_reg  = %08x, data_in3_reg   = %08x", dut.data_in0_reg, dut.data_in1_reg, dut.data_in2_reg, dut.data_in3_reg);
      $display("data_in4_reg  = %08x, data_in5_reg   = %08x, data_in6_reg  = %08x, data_in7_reg   = %08x", dut.data_in4_reg, dut.data_in5_reg, dut.data_in6_reg, dut.data_in7_reg);
      $display("data_in8_reg  = %08x, data_in9_reg   = %08x, data_in10_reg = %08x, data_in11_reg  = %08x", dut.data_in8_reg, dut.data_in9_reg, dut.data_in10_reg, dut.data_in11_reg);
      $display("data_in12_reg = %08x, data_in13_reg  = %08x, data_in14_reg = %08x, data_in15_reg  = %08x", dut.data_in12_reg, dut.data_in13_reg, dut.data_in14_reg, dut.data_in15_reg);
      $display("");
      $display("data_out_valid_reg = %01x", dut.data_out_valid_reg);
      $display("data_out0_reg  = %08x, data_out1_reg   = %08x, data_out2_reg  = %08x, data_out3_reg   = %08x", dut.data_out0_reg, dut.data_out1_reg, dut.data_out2_reg, dut.data_out3_reg);
      $display("data_out4_reg  = %08x, data_out5_reg   = %08x, data_out6_reg  = %08x, data_out7_reg   = %08x", dut.data_out4_reg, dut.data_out5_reg, dut.data_out6_reg, dut.data_out7_reg);
      $display("data_out8_reg  = %08x, data_out9_reg   = %08x, data_out10_reg = %08x, data_out11_reg  = %08x", dut.data_out8_reg, dut.data_out9_reg, dut.data_out10_reg, dut.data_out11_reg);
      $display("data_out12_reg = %08x, data_out13_reg  = %08x, data_out14_reg = %08x, data_out15_reg  = %08x", dut.data_out12_reg, dut.data_out13_reg, dut.data_out14_reg, dut.data_out15_reg);
      $display("");
    end
  endtask // dump_state

  
  //----------------------------------------------------------------
  // chacha_test
  // The main test functionality. 
  //----------------------------------------------------------------
  initial
    begin : chacha_test
      $display("   -- Testbench for chacha started --");
      
      // Set clock, reset and DUT input signals to 
      // defined values at simulation start.
      cycle_ctr     = 0;
      tb_clk        = 0;
      tb_reset_n    = 0;

      tb_cs         = 0;
      tb_write_read = 0;
      tb_address    = 8'h00;
      tb_data_in    = 32'h00000000;
      
      $display("");
      $display("*** State at init.");
      dump_state();
      
      // Wait ten clock cycles and release reset.
      #(4 * CLK_HALF_PERIOD);
      @(negedge tb_clk)
      tb_reset_n = 1;
      dump_state();

      // Try to write a few registers.
      write_reg(8'h10, 32'h55555555);
      write_reg(8'h11, 32'haaaaaaaa);
      dump_state();
      read_reg(8'h10);
      
      // Wait a while and observe what happens.
      #(10 * CLK_HALF_PERIOD);
      dump_state();
      
      // Finish in style.
      $display("*** chacha simulation done.");
      $finish;
    end // chacha_test
  
endmodule // tb_chacha

//======================================================================
// EOF tb_chacha.v
//======================================================================
