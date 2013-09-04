//======================================================================
//
// chacha.v
// --------
// Top level wrapper for the ChaCha stream, cipher core providing
// a simple memory like interface with 32 bit data access.
//
//
// Copyright (c) 2013  Secworks Sweden AB
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

module chacha(
              // Clock and reset.
              input wire           clk,
              input wire           reset_n,
              
              // Control.
              input wire           cs,
              input wire           write_read,
              
              // Data ports.
              input wire  [7 : 0]  address,
              input wire  [31 : 0] data_in,
              output wire [31 : 0] data_out
             );

  
  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter ADDR_CTRL       = 8'h00;
  parameter ADDR_STATUS     = 8'h01;

  parameter ADDR_KEYLEN     = 8'h08;
  parameter ADDR_ROUNDS     = 8'h09;
  
  parameter ADDR_KEY0       = 8'h10;
  parameter ADDR_KEY1       = 8'h11;
  parameter ADDR_KEY2       = 8'h12;
  parameter ADDR_KEY3       = 8'h13;
  parameter ADDR_KEY4       = 8'h14;
  parameter ADDR_KEY5       = 8'h15;
  parameter ADDR_KEY6       = 8'h16;
  parameter ADDR_KEY7       = 8'h17;
                            
  parameter ADDR_IV0        = 8'h20;
  parameter ADDR_IV1        = 8'h21;
                          
  parameter ADDR_DATA_IN0   = 8'h40;
  parameter ADDR_DATA_IN1   = 8'h41;
  parameter ADDR_DATA_IN2   = 8'h42;
  parameter ADDR_DATA_IN3   = 8'h43;
  parameter ADDR_DATA_IN4   = 8'h44;
  parameter ADDR_DATA_IN5   = 8'h45;
  parameter ADDR_DATA_IN6   = 8'h46;
  parameter ADDR_DATA_IN7   = 8'h47;
  parameter ADDR_DATA_IN8   = 8'h48;
  parameter ADDR_DATA_IN9   = 8'h49;
  parameter ADDR_DATA_IN10  = 8'h4a;
  parameter ADDR_DATA_IN11  = 8'h4b;
  parameter ADDR_DATA_IN12  = 8'h4c;
  parameter ADDR_DATA_IN13  = 8'h4d;
  parameter ADDR_DATA_IN14  = 8'h4e;
  parameter ADDR_DATA_IN15  = 8'h4f;

  parameter ADDR_DATA_OUT0  = 8'h80;
  parameter ADDR_DATA_OUT1  = 8'h81;
  parameter ADDR_DATA_OUT2  = 8'h82;
  parameter ADDR_DATA_OUT3  = 8'h83;
  parameter ADDR_DATA_OUT4  = 8'h84;
  parameter ADDR_DATA_OUT5  = 8'h85;
  parameter ADDR_DATA_OUT6  = 8'h86;
  parameter ADDR_DATA_OUT7  = 8'h87;
  parameter ADDR_DATA_OUT8  = 8'h88;
  parameter ADDR_DATA_OUT9  = 8'h89;
  parameter ADDR_DATA_OUT10 = 8'h8a;
  parameter ADDR_DATA_OUT11 = 8'h8b;
  parameter ADDR_DATA_OUT12 = 8'h8c;
  parameter ADDR_DATA_OUT13 = 8'h8d;
  parameter ADDR_DATA_OUT14 = 8'h8e;
  parameter ADDR_DATA_OUT15 = 8'h8f;

  
  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  // Key registers.
  reg [31 : 0] key0_reg;
  reg [31 : 0] key0_new;
  reg          key0_we;
  reg [31 : 0] key1_reg;
  reg [31 : 0] key1_new;
  reg          key1_we;
  reg [31 : 0] key2_reg;
  reg [31 : 0] key2_new;
  reg          key2_we;
  reg [31 : 0] key3_reg;
  reg [31 : 0] key3_new;
  reg          key3_we;
  reg [31 : 0] key4_reg;
  reg [31 : 0] key4_new;
  reg          key4_we;
  reg [31 : 0] key5_reg;
  reg [31 : 0] key5_new;
  reg          key5_we;
  reg [31 : 0] key6_reg;
  reg [31 : 0] key6_new;
  reg          key6_we;
  reg [31 : 0] key7_reg;
  reg [31 : 0] key7_new;
  reg          key7_we;

  // IV registers.
  reg [31 : 0] iv0_reg;
  reg [31 : 0] iv0_new;
  reg          iv0_we;
  reg [31 : 0] iv1_reg;
  reg [31 : 0] iv1_new;
  reg          iv1_we;
  

  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  
  
  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  
  
  //----------------------------------------------------------------
  // reg_update
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with synchronous
  // active low reset. All registers have write enable.
  //----------------------------------------------------------------
  always @ (posedge clk)
    begin
      if (!reset_n)
        begin
          // Reset all registers to defined values.
          key0_reg <= 32'h00000000;
          key1_reg <= 32'h00000000;
          key2_reg <= 32'h00000000;
          key3_reg <= 32'h00000000;
          key4_reg <= 32'h00000000;
          key5_reg <= 32'h00000000;
          key6_reg <= 32'h00000000;
          key7_reg <= 32'h00000000;
          iv0_reg  <= 32'h00000000;
          iv1_reg  <= 32'h00000000;
        end
      else
        begin
          
        end
    end // reg_update

endmodule // chacha

//======================================================================
// EOF chacha.v
//======================================================================
