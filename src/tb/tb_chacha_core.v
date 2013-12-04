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
  
  parameter TC1  = 1;
  parameter TC2  = 2;
  parameter TC3  = 3;
  parameter TC4  = 4;
  parameter TC5  = 5;
  parameter TC6  = 6;
  parameter TC7  = 7;
  parameter TC8  = 8;
  parameter TC9  = 9;
  parameter TC10 = 10;
  
  parameter ONE   = 1;
  parameter TWO   = 2;
  parameter THREE = 3;
  parameter FOUR  = 4;
  parameter FIVE  = 5;
  parameter SIX   = 6;
  parameter SEVEN = 7;
  parameter EIGHT = 8;
  
  parameter KEY_128_BITS = 0;
  parameter KEY_256_BITS = 1;

  parameter EIGHT_ROUNDS  = 8;
  parameter TWELWE_ROUNDS = 12;
  parameter TWENTY_ROUNDS = 20;
  
  parameter DISABLE = 0;
  parameter ENABLE  = 1;
                        
  
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
  reg [0 : 511]  tb_core_data_in;
  wire [0 : 511] tb_core_data_out;

  reg            display_cycle_ctr;
  reg            display_ctrl_and_ctrs;
  reg            display_qround;
  reg            display_state;
  reg            display_x_state;

  
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
  // Monitor that displays different types of information
  // every cycle depending on what flags test cases enable.
  //
  // The monitor includes a cycle counter for the testbench.
  //--------------------------------------------------------------------
  always @ (posedge tb_clk)
    begin : dut_monitor
      cycle_ctr = cycle_ctr + 1;

      // Display cycle counter.
      if (display_cycle_ctr)
        begin
          $display("cycle = %08x:", cycle_ctr);
          $display("");
        end

      // Display FSM control state and QR, DR counters.
      if (display_ctrl_and_ctrs)
        begin
          $display("chacha_ctrl_reg = %01x", dut.chacha_ctrl_reg);
          $display("qr_ctr_reg = %01x, dr_ctr_reg = %01x", dut.qr_ctr_reg, dut.dr_ctr_reg);
          $display("");
        end
      
      // Display the internal state register.
      if (display_state)
        begin
          $display("Internal state:");
          $display("0x%064x", dut.state_reg);
          $display("");
        end
          
      // Display the round processing state register X.
      if (display_x_state)
        begin
          $display("Round state X:");
          $display("x0_reg   = 0x%08x, x0_new   = 0x%08x, x0_we  = 0x%01x", dut.x0_reg,  dut.x0_new,  dut.x0_we);
          $display("x1_reg   = 0x%08x, x1_new   = 0x%08x, x1_we  = 0x%01x", dut.x1_reg,  dut.x1_new,  dut.x1_we);
          $display("x2_reg   = 0x%08x, x2_new   = 0x%08x, x2_we  = 0x%01x", dut.x2_reg,  dut.x2_new,  dut.x2_we);
          $display("x3_reg   = 0x%08x, x3_new   = 0x%08x, x3_we  = 0x%01x", dut.x3_reg,  dut.x3_new,  dut.x3_we);
          $display("x4_reg   = 0x%08x, x4_new   = 0x%08x, x4_we  = 0x%01x", dut.x4_reg,  dut.x4_new,  dut.x4_we);
          $display("x5_reg   = 0x%08x, x5_new   = 0x%08x, x5_we  = 0x%01x", dut.x5_reg,  dut.x5_new,  dut.x5_we);
          $display("x6_reg   = 0x%08x, x6_new   = 0x%08x, x6_we  = 0x%01x", dut.x6_reg,  dut.x6_new,  dut.x6_we);
          $display("x7_reg   = 0x%08x, x7_new   = 0x%08x, x7_we  = 0x%01x", dut.x7_reg,  dut.x7_new,  dut.x7_we);
          $display("x8_reg   = 0x%08x, x8_new   = 0x%08x, x8_we  = 0x%01x", dut.x8_reg,  dut.x8_new,  dut.x8_we);
          $display("x9_reg   = 0x%08x, x9_new   = 0x%08x, x9_we  = 0x%01x", dut.x9_reg,  dut.x9_new,  dut.x9_we);
          $display("x10_reg  = 0x%08x, x10_new  = 0x%08x, x10_we = 0x%01x", dut.x10_reg, dut.x10_new, dut.x10_we);
          $display("x11_reg  = 0x%08x, x11_new  = 0x%08x, x11_we = 0x%01x", dut.x11_reg, dut.x11_new, dut.x11_we);
          $display("x12_reg  = 0x%08x, x12_new  = 0x%08x, x12_we = 0x%01x", dut.x12_reg, dut.x12_new, dut.x12_we);
          $display("x13_reg  = 0x%08x, x13_new  = 0x%08x, x13_we = 0x%01x", dut.x13_reg, dut.x13_new, dut.x13_we);
          $display("x14_reg  = 0x%08x, x14_new  = 0x%08x, x14_we = 0x%01x", dut.x14_reg, dut.x14_new, dut.x14_we);
          $display("x15_reg  = 0x%08x, x15_new  = 0x%08x, x15_we = 0x%01x", dut.x15_reg, dut.x15_new, dut.x15_we);
          $display("");
        end

      // Display the qround input and outputs.
      if (display_qround)
        begin
          $display("a      = %08x, b      = %08x, c      = %08x, d      = %08x", dut.quarterround.a, dut.quarterround.b, dut.quarterround.c, dut.quarterround.d);
          $display("a_prim = %08x, b_prim = %08x, c_prim = %08x, d_prim = %08x", dut.a_prim, dut.b_prim, dut.c_prim, dut.d_prim);
          $display("");
        end
      
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
      $display("0x%064x", dut.state_reg);
      $display("");
      
      $display("Round state X::");
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
      $display("keylen     = %01x", dut.keylen);
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
  // test_quarterround
  //
  // Test the quarterround by forcing the inputs of the logic 
  // to known given values and observing the result.
  //----------------------------------------------------------------
  task test_quarterround(input [31 : 0] a, input [31 : 0] b, 
                         input [31 : 0] c, input [31 : 0] d);
    begin
      $display("Test of quarterround.");
      $display("a = 0x%08x, b = 0x%08x", a, b);
      $display("c = 0x%08x, d = 0x%08x", c, d);
      $display("");
      
      dut.quarterround.a = a;
      dut.quarterround.b = b;
      dut.quarterround.c = c;
      dut.quarterround.d = d;
      #(2 * CLK_HALF_PERIOD);
      
      $display("a0 = 0x%08x, a1 = 0x%08x", dut.quarterround.a0, dut.quarterround.a1);
      $display("b0 = 0x%08x, b1 = 0x%08x", dut.quarterround.b0, dut.quarterround.b1);
      $display("b2 = 0x%08x, b3 = 0x%08x", dut.quarterround.b2, dut.quarterround.b3);
      $display("c0 = 0x%08x, c1 = 0x%08x", dut.quarterround.c0, dut.quarterround.c1);
      $display("d0 = 0x%08x, d1 = 0x%08x", dut.quarterround.d0, dut.quarterround.d1);
      $display("d2 = 0x%08x, d3 = 0x%08x", dut.quarterround.d2, dut.quarterround.d3);
      $display("");
      
      $display("a_prim = 0x%08x, b_prim = 0x%08x", dut.a_prim, dut.b_prim);
      $display("c_prim = 0x%08x, d_prim = 0x%08x", dut.c_prim, dut.d_prim);
      $display("");
    end
  endtask // test_quarterround

  
  //----------------------------------------------------------------
  //----------------------------------------------------------------
  task set_core_init(input value);
    begin
      tb_core_init = value;
    end
  endtask // set_core_init
  
  
  //----------------------------------------------------------------
  //----------------------------------------------------------------
  task set_core_next(input value);
    begin
      tb_core_next = value;
    end
  endtask // set_core_next

  
  //----------------------------------------------------------------
  // set_core_key_iv_rounds()
  //
  // Sets the core key, iv and rounds indata ports 
  // to the given values.
  //----------------------------------------------------------------
  task set_core_key_iv_rounds(input [256 : 0] key, 
                              input           key_length, 
                              input [64 : 0]  iv,
                              input [4 : 0]   rounds);
    begin
      tb_core_key    = key;
      tb_core_keylen = key_length;
      tb_core_iv     = iv;
      tb_core_rounds = rounds;
    end
  endtask // set_core_key_iv

  
  //----------------------------------------------------------------
  // cycle_reset()
  //
  // Cycles the reset signal on the dut.
  //----------------------------------------------------------------
  task cycle_reset();
    begin
      tb_reset_n = 0;
      #(2 * CLK_HALF_PERIOD);

      @(negedge tb_clk)

      tb_reset_n = 1;
      #(2 * CLK_HALF_PERIOD);
    end
  endtask // cycle_reset
  

  //----------------------------------------------------------------
  // run_test_case
  //
  // Runs a test case based on the given key, keylenght, IV and 
  // expected data out from the DUT.
  //----------------------------------------------------------------
  task run_test_case(input [7 : 0]   major, 
                    input [7 : 0]   minor, 
                    input [256 : 0] key, 
                    input           key_length, 
                    input [64 : 0]  iv,
                    input [4 : 0]   rounds,
                    input [512 : 0] expected);
    begin
      $display("*** TC %0d-%0d started.", major, minor);
      $display("");

      cycle_reset();
      set_core_key_iv_rounds(key, key_length, iv, rounds);
      set_core_init(1);
      
      // Wait for valid flag and check results.
      @(posedge dut.data_out_valid);
      if (tb_core_data_out == expected)
        begin
          $display("*** TC %0d-%0d successful", major, minor);
          $display("");
        end 
      else
        begin
          $display("*** ERROR: TC %0d-%0d not successful", major, minor);
          $display("Expected: 0x%064x", expected);
          $display("Got:      0x%064x", tb_core_data_out);
          $display("");
        end
    end
  endtask // test_vectors

  
  //----------------------------------------------------------------
  // chacha_core_test
  // The main test functionality. 
  //----------------------------------------------------------------
  initial
    begin : chacha_core_test
      $display("   -- Testbench for chacha_core started --");
      $display("");
      
      
      $display("*** Test of Quarterround:");
      $display("");
      test_quarterround(32'h11223344, 32'h11223344, 32'h11223344, 32'h11223344);
      test_quarterround(32'h55555555, 32'h55555555, 32'h55555555, 32'h55555555);
        
      // Set clock, reset and DUT input signals to 
      // defined values at simulation start.
      cycle_ctr         = 0;
      tb_clk            = 0;
      tb_reset_n        = 0;

      set_core_key_iv_rounds(256'h0000000000000001000000000000000100000000000000010000000000000001,
                        1'b0,
                        64'h0000000000000001,
                        5'b01000);
      
      tb_core_init      = 0;
      tb_core_next      = 0;
      tb_core_data_in   = 512'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000;

      // Turn of all monitor display functions.
      display_cycle_ctr     = 0;
      display_ctrl_and_ctrs = 0;
      display_state         = 0;
      display_x_state       = 0;
      display_qround        = 0;
     
      // Test of reset functionality.
      // Note: No self test.
      $display("*** State at init:");
      $display("");
      dump_state();
      
      #(4 * CLK_HALF_PERIOD);
      @(negedge tb_clk)
      tb_reset_n = 1;
      #(2 * CLK_HALF_PERIOD);
      $display("*** State after release of reset:");
      $display("");
      dump_state();
      
      // TC1-1: Increasing, decreasing sequences in key and IV.
      // 128 bit key.
     $display("TC1-128-8: All zero inputs. 128 bit key, 8 rounds.");
      run_test_case(TC1, ONE, 
                    256'h0000000000000000000000000000000000000000000000000000000000000000,
                    KEY_128_BITS,
                    64'h0000000000000000,
                    EIGHT_ROUNDS,
                    512'he28a5fa4a67f8c5defed3e6fb7303486aa8427d31419a729572d777953491120b64ab8e72b8deb85cd6aea7cb6089a101824beeb08814a428aab1fa2c816081b);

      
      // TC7-1: Increasing, decreasing sequences in key and IV.
      // 128 bit key.
     $display("TC7-1: Key and IV are increasing, decreasing patterns. 128 bit key.");
      run_test_case(TC7, ONE, 
                    256'h00112233445566778899aabbccddeeff00000000000000000000000000000000,
                    KEY_128_BITS,
                    64'h0f1e2d3c4b596877,
                    EIGHT_ROUNDS,
                    512'h1bc8a6a76e10acd8a1463a8f02c78ebcc7185de95124f4e054fbea9aa2831d47618888bfd2736b5882afea285a5a66f97f865e15fb1b739349ab4fe231b29055);

      
      // TC7-2: Increasing, decreasing sequences in key and IV.
      // 256 bit key.
     $display("TC7-2: Key and IV are increasing, decreasing patterns. 256 bit key.");
      run_test_case(TC7, TWO,
                    256'h00112233445566778899aabbccddeeff00000000000000000000000000000000,
                    KEY_256_BITS,
                    64'h0f1e2d3c4b596877,
                    EIGHT_ROUNDS,
                    512'h1bc8a6a76e10acd8a1463a8f02c78ebcc7185de95124f4e054fbea9aa2831d47618888bfd2736b5882afea285a5a66f97f865e15fb1b739349ab4fe231b29055);

      
      // TC8-1: Random inputs. 128 bit key, 8 rounds.
      $display("TC8-128-8: Random inputs. 128 bit key, 8 rounds.");
      run_test_case(TC8, ONE,
                    256'hc46ec1b18ce8a878725a37e780dfb73500000000000000000000000000000000,
                    KEY_128_BITS,
                    64'h1ada31d5cf688221,
                    EIGHT_ROUNDS,
                    512'h6a870108859f679118f3e205e2a56a6826ef5a60a4102ac8d4770059fcb7c7bae02f5ce004a6bfbbea53014dd82107c0aa1c7ce11b7d78f2d50bd3602bbd2594);
      
        
      // Finish in style.
      $display("*** chacha_core simulation done ***");
      $finish;
    end // chacha_core_test
  
endmodule // tb_chacha_core

//======================================================================
// EOF tb_chacha_core.v
//======================================================================
