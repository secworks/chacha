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

      // Wait a while and observe what happens.
      #(1000 * CLK_HALF_PERIOD);
      
      // Finish in style.
      $display("*** chacha simulation done.");
      $finish;
    end // chacha_test
  
endmodule // tb_chacha

//======================================================================
// EOF tb_chacha.v
//======================================================================
