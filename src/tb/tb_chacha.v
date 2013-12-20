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
  parameter DEBUG = 0;

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

  // API for the dut.
  parameter ADDR_CTRL        = 8'h00;
  parameter CTRL_INIT_BIT    = 0;
  parameter CTRL_NEXT_BIT    = 1;

  parameter ADDR_STATUS      = 8'h01;
  parameter STATUS_READY_BIT = 0;
  
  parameter ADDR_KEYLEN      = 8'h08;
  parameter KEYLEN_BIT       = 0;
  parameter ADDR_ROUNDS      = 8'h09;
  parameter ROUNDS_HIGH_BIT  = 4;
  parameter ROUNDS_LOW_BIT   = 0;
                             
  parameter ADDR_KEY0        = 8'h10;
  parameter ADDR_KEY1        = 8'h11;
  parameter ADDR_KEY2        = 8'h12;
  parameter ADDR_KEY3        = 8'h13;
  parameter ADDR_KEY4        = 8'h14;
  parameter ADDR_KEY5        = 8'h15;
  parameter ADDR_KEY6        = 8'h16;
  parameter ADDR_KEY7        = 8'h17;
                             
  parameter ADDR_IV0         = 8'h20;
  parameter ADDR_IV1         = 8'h21;
                             
  parameter ADDR_DATA_IN0    = 8'h40;
  parameter ADDR_DATA_IN1    = 8'h41;
  parameter ADDR_DATA_IN2    = 8'h42;
  parameter ADDR_DATA_IN3    = 8'h43;
  parameter ADDR_DATA_IN4    = 8'h44;
  parameter ADDR_DATA_IN5    = 8'h45;
  parameter ADDR_DATA_IN6    = 8'h46;
  parameter ADDR_DATA_IN7    = 8'h47;
  parameter ADDR_DATA_IN8    = 8'h48;
  parameter ADDR_DATA_IN9    = 8'h49;
  parameter ADDR_DATA_IN10   = 8'h4a;
  parameter ADDR_DATA_IN11   = 8'h4b;
  parameter ADDR_DATA_IN12   = 8'h4c;
  parameter ADDR_DATA_IN13   = 8'h4d;
  parameter ADDR_DATA_IN14   = 8'h4e;
  parameter ADDR_DATA_IN15   = 8'h4f;
                             
  parameter ADDR_DATA_OUT0   = 8'h80;
  parameter ADDR_DATA_OUT1   = 8'h81;
  parameter ADDR_DATA_OUT2   = 8'h82;
  parameter ADDR_DATA_OUT3   = 8'h83;
  parameter ADDR_DATA_OUT4   = 8'h84;
  parameter ADDR_DATA_OUT5   = 8'h85;
  parameter ADDR_DATA_OUT6   = 8'h86;
  parameter ADDR_DATA_OUT7   = 8'h87;
  parameter ADDR_DATA_OUT8   = 8'h88;
  parameter ADDR_DATA_OUT9   = 8'h89;
  parameter ADDR_DATA_OUT10  = 8'h8a;
  parameter ADDR_DATA_OUT11  = 8'h8b;
  parameter ADDR_DATA_OUT12  = 8'h8c;
  parameter ADDR_DATA_OUT13  = 8'h8d;
  parameter ADDR_DATA_OUT14  = 8'h8e;
  parameter ADDR_DATA_OUT15  = 8'h8f;
  
  
  //----------------------------------------------------------------
  // Register and Wire declarations.
  //----------------------------------------------------------------
  reg tb_clk;
  reg tb_reset_n;

  reg           tb_cs;
  reg           tb_write_read;

  reg  [7 : 0]  tb_address;
  reg  [31 : 0] tb_data_in;
  wire [31 : 0] tb_data_out;

  reg [63 : 0] cycle_ctr;
  reg [31 : 0] error_ctr;
  reg [31 : 0] tc_ctr;
  
  reg          error_found;
  reg [31 : 0] read_data;
  
  reg [511 : 0] extracted_data;
  
  reg display_cycle_ctr;
  reg display_read_write;
  
  
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
  //
  // Clock generator process. 
  //----------------------------------------------------------------
  always 
    begin : clk_gen
      #CLK_HALF_PERIOD tb_clk = !tb_clk;
    end // clk_gen

  
  //--------------------------------------------------------------------
  // dut_monitor
  //
  // Monitor displaying information every cycle.
  // Includes the cycle counter.
  //--------------------------------------------------------------------
  always @ (posedge tb_clk)
    begin : dut_monitor
      cycle_ctr = cycle_ctr + 1;

      if (display_cycle_ctr)
        begin
          $display("cycle = %016x:", cycle_ctr);
        end

      if (display_read_write)
        begin
          
          if (dut.cs)
            begin
              if (dut.write_read)
                begin
                  $display("*** Write acess: addr 0x%02x = 0x%08x", dut.address, dut.data_in);
                end
              else
                begin
                  $display("*** Read acess: addr 0x%02x = 0x%08x", dut.address, dut.data_out_reg);
                end
            end
        end
      
    end // dut_monitor

  
  //----------------------------------------------------------------
  // set_display_prefs()
  //
  // Set the different monitor displays we want to see during
  // simulation.
  //----------------------------------------------------------------
  task set_display_prefs(
                         input cycles, 
                         input read_write);
    begin
      display_cycle_ctr  = cycles;
      display_read_write = read_write;
    end
  endtask // set_display_prefs

  
  //----------------------------------------------------------------
  // reset_dut
  //----------------------------------------------------------------
  task reset_dut();
    begin
      tb_reset_n = 0;
      #(4 * CLK_HALF_PERIOD);
      tb_reset_n = 1;
    end
  endtask // reset_dut

  
  //----------------------------------------------------------------
  // read_reg
  //
  // Task that reads and display the value of 
  // a register in the dut.
  //----------------------------------------------------------------
  task read_reg(input [7 : 0] addr);
    begin
      tb_cs         = 1;
      tb_write_read = 0;
      tb_address    = addr;
      #(2 * CLK_HALF_PERIOD);
      tb_cs         = 0;
      tb_write_read = 0;
      tb_address    = 8'h00;
      tb_data_in    = 32'h00000000;
    end
  endtask // read_reg


  //----------------------------------------------------------------
  // write_reg
  //
  // Task that writes to a register in the dut.
  //----------------------------------------------------------------
  task write_reg(input [7 : 0] addr, input [31 : 0] data);
    begin
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
  // dump_top_state
  //
  // Dump the internal state of the top to std out.
  //----------------------------------------------------------------
  task dump_top_state();
    begin
      $display("");
      $display("Top internal state");
      $display("------------------");
      $display("init_reg   = %01x", dut.init_reg);
      $display("next_reg   = %01x", dut.next_reg);
      $display("ready_reg  = %01x", dut.ready_reg);
      $display("keylen_reg = %01x", dut.keylen_reg);
      $display("rounds_reg = %01x", dut.rounds_reg);
      $display("");

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
  endtask // dump_top_state


  //----------------------------------------------------------------
  // dump_core_state
  //
  // Dump the internal state of the core to std out.
  //----------------------------------------------------------------
  task dump_core_state();
    begin
      $display("");
      $display("Core internal state");
      $display("-------------------");
//      $display("Internal data state vector:");
//      $display("0x%064x", dut.core.state_reg);
      $display("");
      
      $display("Round state X:");
      $display("x0_reg  = %08x, x1_reg  = %08x", dut.core.x0_reg, dut.core.x1_reg);
      $display("x2_reg  = %08x, x3_reg  = %08x", dut.core.x2_reg, dut.core.x3_reg);
      $display("x4_reg  = %08x, x5_reg  = %08x", dut.core.x4_reg, dut.core.x5_reg);
      $display("x6_reg  = %08x, x7_reg  = %08x", dut.core.x6_reg, dut.core.x7_reg);
      $display("x8_reg  = %08x, x9_reg  = %08x", dut.core.x8_reg, dut.core.x9_reg);
      $display("x10_reg = %08x, x11_reg = %08x", dut.core.x10_reg, dut.core.x11_reg);
      $display("x12_reg = %08x, x13_reg = %08x", dut.core.x12_reg, dut.core.x13_reg);
      $display("x14_reg = %08x, x15_reg = %08x", dut.core.x14_reg, dut.core.x15_reg);
      $display("");
      
      $display("rounds_reg = %01x", dut.core.rounds_reg);
      $display("qr_ctr_reg = %01x, dr_ctr_reg  = %01x", dut.core.qr_ctr_reg, dut.core.dr_ctr_reg);
      $display("block0_ctr_reg = %08x, block1_ctr_reg = %08x", dut.core.block0_ctr_reg, dut.core.block1_ctr_reg);

      $display("");

      $display("chacha_ctrl_reg = %02x", dut.core.chacha_ctrl_reg);
      $display("");

      $display("data_in_reg = %064x", dut.core.data_in_reg);
      $display("data_out_valid_reg = %01x", dut.core.data_out_valid_reg);
      $display("");

      $display("qr0_a_prim = %08x, qr0_b_prim = %08x", dut.core.qr0_a_prim, dut.core.qr0_b_prim);
      $display("qr0_c_prim = %08x, qr0_d_prim = %08x", dut.core.qr0_c_prim, dut.core.qr0_d_prim);
      $display("");
    end
  endtask // dump_core_state

  
  //----------------------------------------------------------------
  // display_test_result()
  //
  // Display the accumulated test results.
  //----------------------------------------------------------------
  task display_test_result();
    begin
      if (error_ctr == 0)
        begin
          $display("*** All %02d test cases completed successfully", tc_ctr);
        end
      else
        begin
          $display("*** %02d test cases did not complete successfully.", error_ctr);
        end
    end
  endtask // display_test_result
  
    
  //----------------------------------------------------------------
  // init_dut()
  //
  // Set the input to the DUT to defined values.
  //----------------------------------------------------------------
  task init_dut();
    begin
      // Set clock, reset and DUT input signals to 
      // defined values at simulation start.
      cycle_ctr     = 0;
      error_ctr     = 0;
      tc_ctr        = 0;
      tb_clk        = 0;
      tb_reset_n    = 0;
      tb_cs         = 0;
      tb_write_read = 0;
      tb_address    = 8'h00;
      tb_data_in    = 32'h00000000;
    end
  endtask // init_dut

  
  //----------------------------------------------------------------
  // read_write_test()
  //
  // Simple test case that tries to read and write to the
  // registers in the dut.
  //
  // Note: Currently not self testing. No expected values.
  //----------------------------------------------------------------
  task read_write_test();
    begin
      tc_ctr = tc_ctr + 1;
      
      write_reg(ADDR_KEY0, 32'h55555555);
      read_reg(ADDR_KEY0);
      write_reg(ADDR_KEY1, 32'haaaaaaaa);
      read_reg(ADDR_KEY1);
      read_reg(ADDR_CTRL);
      read_reg(ADDR_STATUS);
      read_reg(ADDR_KEYLEN);
      read_reg(ADDR_ROUNDS);

      read_reg(ADDR_KEY0);
      read_reg(ADDR_KEY1);
      read_reg(ADDR_KEY2);
      read_reg(ADDR_KEY3);
      read_reg(ADDR_KEY4);
      read_reg(ADDR_KEY5);
      read_reg(ADDR_KEY6);
      read_reg(ADDR_KEY7);
    end
  endtask // read_write_test


  //----------------------------------------------------------------
  // write_parameters()
  //
  // Write key, iv and other parameters to the dut.
  //----------------------------------------------------------------
  task write_parameters(input [256 : 0] key, 
                            input           key_length, 
                            input [64 : 0]  iv,
                            input [4 : 0]   rounds);
    begin
      write_reg(ADDR_KEY0, key[255 : 224]);
      write_reg(ADDR_KEY1, key[223 : 192]);
      write_reg(ADDR_KEY2, key[191 : 160]);
      write_reg(ADDR_KEY3, key[159 : 128]);
      write_reg(ADDR_KEY4, key[127 :  96]);
      write_reg(ADDR_KEY5, key[95  :  64]);
      write_reg(ADDR_KEY6, key[63  :  32]);
      write_reg(ADDR_KEY7, key[31 :    0]);
      write_reg(ADDR_IV0, iv[63 : 32]);
      write_reg(ADDR_IV1, iv[31 : 0]);
      write_reg(ADDR_KEYLEN, {{31'b0000000000000000000000000000000}, key_length});
      write_reg(ADDR_ROUNDS, {{27'b000000000000000000000000000}, rounds});
    end
  endtask // write_parameters

    
  //----------------------------------------------------------------
  // start_init_block()
  //
  // Toggle the init signal in the dut to make it start processing
  // the first block available in the data in registers.
  //
  // Note: It is the callers responsibility to call the function
  // when the dut is ready to react on the init signal.
  //----------------------------------------------------------------
  task start_init_block();
    begin
      write_reg(ADDR_CTRL, 32'h00000001);
      #(4 * CLK_HALF_PERIOD);
      write_reg(ADDR_CTRL, 32'h00000000);
    end
  endtask // start_init_block
  
    
  //----------------------------------------------------------------
  // start_next_block()
  //
  // Toggle the next signal in the dut to make it start processing
  // the next block available in the data in registers.
  //
  // Note: It is the callers responsibility to call the function
  // when the dut is ready to react on the next signal.
  //----------------------------------------------------------------
  task start_next_block();
    begin
      write_reg(ADDR_CTRL, 32'h00000002);
      #(4 * CLK_HALF_PERIOD);
      write_reg(ADDR_CTRL, 32'h00000000);

      if (DEBUG)
        begin
          $display("Debug of next state.");
          dump_core_state();
          #(4 * CLK_HALF_PERIOD);
          dump_core_state();
        end
    end
  endtask // start_next_block
  

  //----------------------------------------------------------------
  // wait_ready()
  //
  // Wait for the ready flag in the dut to be set.
  //
  // Note: It is the callers responsibility to call the function
  // when the dut is actively processing and will in fact at some
  // point set the flag.
  //----------------------------------------------------------------
  task wait_ready();
    begin
      while (!tb_data_out[STATUS_READY_BIT])
        begin
          read_reg(ADDR_STATUS);
        end
    end
  endtask // wait_ready


  //----------------------------------------------------------------
  // extract_data()
  //
  // Extracts all 16 data out words and combine them into the
  // global extracted_data.
  //----------------------------------------------------------------
  task extract_data();
    begin
      read_reg(ADDR_DATA_OUT0);
      extracted_data[511 : 480] = tb_data_out;
      read_reg(ADDR_DATA_OUT1);
      extracted_data[479 : 448] = tb_data_out;
      read_reg(ADDR_DATA_OUT2);
      extracted_data[447 : 416] = tb_data_out;
      read_reg(ADDR_DATA_OUT3);
      extracted_data[415 : 384] = tb_data_out;
      read_reg(ADDR_DATA_OUT4);
      extracted_data[383 : 352] = tb_data_out;
      read_reg(ADDR_DATA_OUT5);
      extracted_data[351 : 320] = tb_data_out;
      read_reg(ADDR_DATA_OUT6);
      extracted_data[319 : 288] = tb_data_out;
      read_reg(ADDR_DATA_OUT7);
      extracted_data[287 : 256] = tb_data_out;
      read_reg(ADDR_DATA_OUT8);
      extracted_data[255 : 224] = tb_data_out;
      read_reg(ADDR_DATA_OUT9);
      extracted_data[223 : 192] = tb_data_out;
      read_reg(ADDR_DATA_OUT10);
      extracted_data[191 : 160] = tb_data_out;
      read_reg(ADDR_DATA_OUT11);
      extracted_data[159 : 128] = tb_data_out;
      read_reg(ADDR_DATA_OUT12);
      extracted_data[127 :  96] = tb_data_out;
      read_reg(ADDR_DATA_OUT13);
      extracted_data[95  :  64] = tb_data_out;
      read_reg(ADDR_DATA_OUT14);
      extracted_data[63  :  32] = tb_data_out;
      read_reg(ADDR_DATA_OUT15);
      extracted_data[31  :   0] = tb_data_out;
    end
  endtask // extract_data
  
    
  //----------------------------------------------------------------
  // run_two_blocks_test_vector()
  //
  // Runs a test case with two blocks based on the given 
  // test vector. Only the final block is compared.
  //----------------------------------------------------------------
  task run_two_blocks_test_vector(input [7 : 0]   major, 
                                  input [7 : 0]   minor, 
                                  input [256 : 0] key, 
                                  input           key_length, 
                                  input [64 : 0]  iv,
                                  input [4 : 0]   rounds,
                                  input [511 : 0] expected);
    begin
      tc_ctr = tc_ctr + 1;
      
      $display("***TC%2d-%2d started", major, minor);
      $display("***-----------------");
      write_parameters(key, key_length, iv, rounds);

      start_init_block();
      wait_ready();
      extract_data();

      if (DEBUG)
        begin
          $display("State after first block:");
          dump_core_state();
          
          $display("First block:");
          $display("0x%064x", extracted_data);
        end
      
      start_next_block();

      if (DEBUG)
        begin
          $display("State after init of second block:");
          dump_core_state();
        end

      wait_ready();
      extract_data();

      if (DEBUG)
        begin
          $display("State after init of second block:");
          dump_core_state();
          
          $display("Second block:");
          $display("0x%064x", extracted_data);
        end
      
      if (extracted_data != expected)
        begin
          error_ctr = error_ctr + 1;
          $display("***TC%2d-%2d - ERROR", major, minor);
          $display("***-----------------");
          $display("Expected:");
          $display("0x%064x", expected);
          $display("Got:");
          $display("0x%064x", extracted_data);
        end
      else
        begin
          $display("***TC%2d-%2d - SUCCESS", major, minor);
          $display("***-------------------");
        end
      $display("");
    end
  endtask // run_two_blocks_test_vector
  
    
  //----------------------------------------------------------------
  // run_test_vector()
  //
  // Runs a test case based on the given test vector.
  //----------------------------------------------------------------
  task run_test_vector(input [7 : 0]   major, 
                       input [7 : 0]   minor, 
                       input [256 : 0] key, 
                       input           key_length, 
                       input [64 : 0]  iv,
                       input [4 : 0]   rounds,
                       input [511 : 0] expected);
    begin
      tc_ctr = tc_ctr + 1;
      
      $display("***TC%2d-%2d started", major, minor);
      $display("***-----------------");
      write_parameters(key, key_length, iv, rounds);

      start_init_block();
      wait_ready();
      extract_data();
      
      if (extracted_data != expected)
        begin
          error_ctr = error_ctr + 1;
          $display("***TC%2d-%2d - ERROR", major, minor);
          $display("***-----------------");
          $display("Expected:");
          $display("0x%064x", expected);
          $display("Got:");
          $display("0x%064x", extracted_data);
        end
      else
        begin
          $display("***TC%2d-%2d - SUCCESS", major, minor);
          $display("***-------------------");
        end
      $display("");
    end
  endtask // run_test_vector
    
    
  //----------------------------------------------------------------
  // chacha_test
  // The main test functionality. 
  //----------------------------------------------------------------
  initial
    begin : chacha_test
      $display("   -- Testbench for chacha started --");
      init_dut();
      set_display_prefs(0, 0);
      reset_dut();

      $display("State at init after reset:");
      dump_top_state();

      $display("TC1-1: All zero inputs. 128 bit key, 8 rounds.");
      run_test_vector(TC1, ONE, 
                    256'h0000000000000000000000000000000000000000000000000000000000000000,
                    KEY_128_BITS,
                    64'h0000000000000000,
                    EIGHT_ROUNDS,
                    512'he28a5fa4a67f8c5defed3e6fb7303486aa8427d31419a729572d777953491120b64ab8e72b8deb85cd6aea7cb6089a101824beeb08814a428aab1fa2c816081b);

      $display("TC7-2: Increasing, decreasing sequences in key and IV. 256 bit key, 8 rounds.");
      run_test_vector(TC7, TWO,
                    256'h00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100,                    
                    KEY_256_BITS,
                    64'h0f1e2d3c4b596877,
                    EIGHT_ROUNDS,
                    512'h60fdedbd1a280cb741d0593b6ea0309010acf18e1471f68968f4c9e311dca149b8e027b47c81e0353db013891aa5f68ea3b13dd2f3b8dd0873bf3746e7d6c567);


      $display("TC7-3: Increasing, decreasing sequences in key and IV. 256 bit key, 8 rounds.");
      $display("TC7-3: Testing correct second block.");
      run_two_blocks_test_vector(TC7, THREE,
                                 256'h00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100,                    
                                 KEY_256_BITS,
                                 64'h0f1e2d3c4b596877,
                                 EIGHT_ROUNDS,
                                 512'hfe882395601ce8aded444867fe62ed8741420002e5d28bb573113a418c1f4008e954c188f38ec4f26bb8555e2b7c92bf4380e2ea9e553187fdd42821794416de);
      
      
      display_test_result();
      $display("*** chacha simulation done.");
      $finish;
    end // chacha_test
endmodule // tb_chacha

//======================================================================
// EOF tb_chacha.v
//======================================================================
