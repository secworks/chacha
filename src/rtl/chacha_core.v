//======================================================================
//
// chacha_core.v
// --------------
// Verilog 2001 implementation of the stream cipher ChaCha.
// This is the internal core with wide interfaces.
//
//
// Copyright (c) 2013// , Secworks Sweden AB
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

module chacha_core(
                   // Clock and reset.
                   input wire            clk,
                   input wire            reset_n,
                
                   // Control.
                   input wire            init,
                   input wire            next,

                   // Parameters.
                   input wire [255 : 0]  key,
                   input wire            key_length,
                   input wire [63 : 0]   iv,
                   input wire [4 : 0]    rounds,
                   
                   // Data input.
                   input wire [511 : 0]  data_in,
                   
                   // Status output.
                   output wire           ready,
                    
                   // Data out with valid signal.
                   output wire [511 : 0] data_out,
                   output wire           data_out_valid
                  );

  
  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  // Datapath quartterround states names.
  parameter QR0 = 3'h0;
  parameter QR1 = 3'h0;
  parameter QR2 = 3'h0;
  parameter QR3 = 3'h0;
  parameter QR4 = 3'h0;
  parameter QR5 = 3'h0;
  parameter QR6 = 3'h0;
  parameter QR7 = 3'h0;

  // NUM_ROUNDS
  // Default number of rounds
  parameter NUM_ROUNDS = 4'h8;

  // TAU and SIGMA constants.
  parameter TAU0 = 32'h61707865;
  parameter TAU1 = 32'h3120646e;
  parameter TAU2 = 32'h79622d36;
  parameter TAU3 = 32'h6b206574;

  parameter SIGMA0 = 32'h61707865;
  parameter SIGMA1 = 32'h3320646e;
  parameter SIGMA2 = 32'h79622d32;
  parameter SIGMA3 = 32'h6b206574;
  
  // State names for the control FSM.
  parameter CTRL_IDLE   = 3'h0;
  parameter CTRL_ROUNDS = 3'h1;
  parameter CTRL_DONE   = 3'h2;

  
  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  // x0..x15
  // 16 internal state registers including update vectors 
  // and write enable signals.
  reg [31 : 0] x0_reg;
  reg [31 : 0] x0_new;
  reg          x0_we;
  
  reg [31 : 0] x1_reg;
  reg [31 : 0] x1_new;
  reg          x1_we;
  
  reg [31 : 0] x2_reg;
  reg [31 : 0] x2_new;
  reg          x2_we;
  
  reg [31 : 0] x3_reg;
  reg [31 : 0] x3_new;
  reg          x3_we;
  
  reg [31 : 0] x4_reg;
  reg [31 : 0] x4_new;
  reg          x4_we;
  
  reg [31 : 0] x5_reg;
  reg [31 : 0] x5_new;
  reg          x5_we;
  
  reg [31 : 0] x6_reg;
  reg [31 : 0] x6_new;
  reg          x6_we;
  
  reg [31 : 0] x7_reg;
  reg [31 : 0] x7_new;
  reg          x7_we;
  
  reg [31 : 0] x8_reg;
  reg [31 : 0] x8_new;
  reg          x8_we;
  
  reg [31 : 0] x9_reg;
  reg [31 : 0] x9_new;
  reg          x9_we;
  
  reg [31 : 0] x10_reg;
  reg [31 : 0] x10_new;
  reg          x10_we;
  
  reg [31 : 0] x11_reg;
  reg [31 : 0] x11_new;
  reg          x11_we;
  
  reg [31 : 0] x12_reg;
  reg [31 : 0] x12_new;
  reg          x12_we;
  
  reg [31 : 0] x13_reg;
  reg [31 : 0] x13_new;
  reg          x13_we;
  
  reg [31 : 0] x14_reg;
  reg [31 : 0] x14_new;
  reg          x14_we;
  
  reg [31 : 0] x15_reg;
  reg [31 : 0] x15_new;
  reg          x15_we;

  reg [511 : 0] data_in_reg;
  reg           data_in_we;

  // Note: 4 bits since we count double rounds.
  reg [3 : 0] rounds_reg;
  reg         rounds_we;
  
  reg  data_out_valid_reg;
  reg  data_out_valid_new;
  reg  data_out_valid_we;

  // Quarterround counter register with
  // reset and increment control.
  reg [2 : 0] qr_ctr_reg;
  reg [2 : 0] qr_ctr_new;
  reg         qr_ctr_we;
  reg         qr_ctr_inc;
  reg         qr_ctr_rst;
  
  // Doubleround counter register with
  // reset and increment control.
  reg [3 : 0] dr_ctr_reg;
  reg [3 : 0] dr_ctr_new;
  reg         dr_ctr_we;
  reg         dr_ctr_inc;
  reg         dr_ctr_rst;

  // 64 bit block counter based on two
  // 32 bit words with reset and 
  // increment control.
  reg [31 : 0] block0_ctr_reg;
  reg [31 : 0] block0_ctr_new;
  reg [31 : 0] block1_ctr_reg;
  reg [31 : 0] block1_ctr_new;
  reg          block0_ctr_we;
  reg          block1_ctr_we;
  reg          block_ctr_inc;
  reg          block_ctr_rst;
  
  reg [2 : 0] chacha_ctrl_reg;
  reg [2 : 0] chacha_ctrl_new;
  reg         chacha_ctrl_we;
  
  
  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg init_cipher;
  reg init_round;
  reg next_block;
  reg update_dp;
  reg finalize;

  // Wires to connect the pure combinational quarterround 
  // to the state update logic.
  reg [31 : 0] a_prim;
  reg [31 : 0] b_prim;
  reg [31 : 0] c_prim;
  reg [31 : 0] d_prim;
  
  // ready flag wire.
  reg ready_wire;
  
  
  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  // Data out assignment. Note that this adds one layer of XOR
  assign data_out = data_in ^ {x15_reg, x14_reg, x13_reg, x12_reg, 
                               x11_reg, x10_reg, x9_reg, x8_reg, 
                               x7_reg, x6_reg, x5_reg, x4_reg, 
                               x3_reg, x2_reg, x1_reg, x0_reg};

  assign data_out_valid = data_out_valid_reg;
  
  assign ready = ready_wire;
  
  
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
          x0_reg             <= 32'h00000000;
          x1_reg             <= 32'h00000000;
          x2_reg             <= 32'h00000000;
          x3_reg             <= 32'h00000000;
          x4_reg             <= 32'h00000000;
          x5_reg             <= 32'h00000000;
          x6_reg             <= 32'h00000000;
          x7_reg             <= 32'h00000000;
          x8_reg             <= 32'h00000000;
          x9_reg             <= 32'h00000000;
          x10_reg            <= 32'h00000000;
          x11_reg            <= 32'h00000000;
          x12_reg            <= 32'h00000000;
          x13_reg            <= 32'h00000000;
          x14_reg            <= 32'h00000000;
          x15_reg            <= 32'h00000000;
          data_in_reg        <= 512'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000;
          rounds_reg         <= 4'h0;
          data_out_valid_reg <= 0;
          qr_ctr_reg         <= QR0;
          dr_ctr_reg         <= 0;
          block0_ctr_reg     <= 32'h00000000;
          block1_ctr_reg     <= 32'h00000000;
          chacha_ctrl_reg    <= CTRL_IDLE;
        end
      else
        begin
          if (x0_we)
            begin
              x0_reg <= x0_new;
            end

          if (x1_we)
            begin
              x1_reg <= x1_new;
            end

          if (x2_we)
            begin
              x2_reg <= x2_new;
            end

          if (x3_we)
            begin
              x3_reg <= x3_new;
            end

          if (x4_we)
            begin
              x4_reg <= x4_new;
            end

          if (x5_we)
            begin
              x5_reg <= x5_new;
            end

          if (x6_we)
            begin
              x6_reg <= x6_new;
            end

          if (x7_we)
            begin
              x7_reg <= x7_new;
            end

          if (x8_we)
            begin
              x8_reg <= x8_new;
            end

          if (x9_we)
            begin
              x9_reg <= x9_new;
            end

          if (x10_we)
            begin
              x10_reg <= x10_new;
            end

          if (x11_we)
            begin
              x11_reg <= x11_new;
            end

          if (x12_we)
            begin
              x12_reg <= x12_new;
            end

          if (x13_we)
            begin
              x13_reg <= x13_new;
            end

          if (x14_we)
            begin
              x14_reg <= x14_new;
            end

          if (x15_we)
            begin
              x15_reg <= x15_new;
            end

          if (data_out_valid_we)
            begin
              data_out_valid_reg <= data_out_valid_new;
            end

          if (qr_ctr_we)
            begin
              qr_ctr_reg <= qr_ctr_new;
            end

          if (dr_ctr_we)
            begin
              dr_ctr_reg <= dr_ctr_new;
            end

          if (data_in_we)
            begin
              data_in_reg <= data_in;
            end

          // Note we skip the low bit.
          if (rounds_we)
            begin
              rounds_reg <= rounds[4 : 1];
            end
          
          if (chacha_ctrl_we)
            begin
              chacha_ctrl_reg <= chacha_ctrl_new;
            end
        end
    end // reg_update


  //----------------------------------------------------------------
  // Quarterround logic including MUX to select state registers
  // as inputs to the quarterround.
  //----------------------------------------------------------------
  always @*
    begin : quarterround
      // Internal wires for the quartterround
      reg [31 : 0] a;
      reg [31 : 0] a0;
      reg [31 : 0] a1;

      reg [31 : 0] b;
      reg [31 : 0] b0;
      reg [31 : 0] b1;
      reg [31 : 0] b2;
      reg [31 : 0] b3;
      
      reg [31 : 0] c;
      reg [31 : 0] c0;
      reg [31 : 0] c1;
      reg [31 : 0] c2;
      reg [31 : 0] c3;
      
      reg [31 : 0] d;
      reg [31 : 0] d0;
      reg [31 : 0] d1;
      reg [31 : 0] d2;
      reg [31 : 0] d3;
      
      // MUX for selecting registers for the quarterround.
      case (qr_ctr_reg)
          QR0:
            begin
              a = x0_reg;
              b = x4_reg;
              c = x8_reg;
              d = x12_reg;
            end
        
          QR1:
            begin
              a = x1_reg;
              b = x5_reg;
              c = x9_reg;
              d = x13_reg;
            end
        
          QR2:
            begin
              a = x2_reg;
              b = x6_reg;
              c = x10_reg;
              d = x14_reg;
            end
        
          QR3:
            begin
              a = x3_reg;
              b = x7_reg;
              c = x11_reg;
              d = x15_reg;
            end
        
          QR4:
            begin
              a = x0_reg;
              b = x5_reg;
              c = x10_reg;
              d = x15_reg;
            end
        
          QR5:
            begin
              a = x1_reg;
              b = x6_reg;
              c = x11_reg;
              d = x12_reg;
            end
        
          QR6:
            begin
              a = x2_reg;
              b = x7_reg;
              c = x8_reg;
              d = x13_reg;
            end
        
          QR7:
            begin
              a = x3_reg;
              b = x4_reg;
              c = x9_reg;
              d = x14_reg;
            end
      endcase // case (quarterround_select)
        
      // The actual quarterround logic
      a0     = a + b;
      d0     = d ^ a0;
      d1     = {d0[15:0], d0[31:16]};
      c0     = c + d1;
      b0     = b ^ c0;
      b1     = {b0[20:0], b0[31:21]};
      a1     = a0 + b1;
      d2     = d1 ^ a1;
      d3     = {d2[23:0], d2[31:24]};
      c1     = c0 + d3;
      b2     = b1 ^ c1;
      b3     = {b2[24:0], b2[31:25]};

      a_prim = a1;
      b_prim = b3;
      c_prim = c1;
      d_prim = d3;
    end // quarterround


  //----------------------------------------------------------------
  // state_update
  //
  // Logic to update the internal state during initialization
  // as well as round processing.
  //----------------------------------------------------------------
  always @*
    begin : state_update
      // Default assignments
      x0_new = 32'h00000000;
      x0_we  = 0;
      x1_new = 32'h00000000;
      x1_we  = 0;
      x2_new = 32'h00000000;
      x2_we  = 0;
      x3_new = 32'h00000000;
      x3_we  = 0;
      x4_new = 32'h00000000;
      x4_we  = 0;
      x5_new = 32'h00000000;
      x5_we  = 0;
      x6_new = 32'h00000000;
      x6_we  = 0;
      x7_new = 32'h00000000;
      x7_we  = 0;
      x8_new = 32'h00000000;
      x8_we  = 0;
      x9_new = 32'h00000000;
      x9_we  = 0;
      x10_new = 32'h00000000;
      x10_we  = 0;
      x11_new = 32'h00000000;
      x11_we  = 0;
      x12_new = 32'h00000000;
      x12_we  = 0;
      x13_new = 32'h00000000;
      x13_we  = 0;
      x14_new = 32'h00000000;
      x14_we  = 0;
      x15_new = 32'h00000000;
      x15_we  = 0;

      if (init_cipher)
        begin
          x0_we   = 1;
          x1_we   = 1;
          x2_we   = 1;
          x3_we   = 1;
          x4_we   = 1;
          x5_we   = 1;
          x6_we   = 1;
          x7_we   = 1;
          x8_we   = 1;
          x9_we   = 1;
          x10_we  = 1;
          x11_we  = 1;
          x12_we  = 1;
          x13_we  = 1;
          x14_we  = 1;
          x15_we  = 1;
          x4_new  = key[31 : 0];
          x5_new  = key[63 : 32];
          x6_new  = key[95 : 64];
          x7_new  = key[127 : 96];
          x12_new = 32'h00000000;
          x13_new = 32'h00000000;
          x14_new = iv[31 : 0];
          x15_new = iv[63 : 0];

          if (key_length)
            begin
              // 256 bit key.
              x0_new  = SIGMA0;
              x1_new  = SIGMA1;
              x2_new  = SIGMA2;
              x3_new  = SIGMA3;
              x8_new  = key[159 : 128];
              x9_new  = key[191 : 160];
              x10_new = key[223 : 192];
              x11_new = key[255 : 224];
            end
          else
            begin
              // 128 bit key.
              x0_new  = TAU0;
              x1_new  = TAU1;
              x2_new  = TAU2;
              x3_new  = TAU3;
              x8_new  = key[31 : 0];
              x9_new  = key[63 : 32];
              x10_new = key[95 : 64];
              x11_new = key[127 : 96];
            end
        end // if (init_cipher)

      else if (init_round)
        begin
          x12_new = block0_ctr_reg;
          x12_we  = 1;
          x13_new = block1_ctr_reg;
          x13_we  = 1;
        end
      
      else if (update_dp)
        begin
          // Quarterround update.
          // Write results from the quarterround to the state regs.
          x0_new  = a_prim;
          x1_new  = a_prim; 
          x2_new  = a_prim;
          x3_new  = a_prim;

          x4_new  = b_prim;
          x5_new  = b_prim;
          x6_new  = b_prim;
          x7_new  = b_prim;

          x8_new  = c_prim;
          x9_new  = c_prim;
          x10_new = c_prim;
          x11_new = c_prim; 

          x12_new = d_prim;
          x13_new = d_prim;
          x14_new = d_prim;
          x15_new = d_prim;
          
          case (qr_ctr_reg)
            QR0:
              begin
                x0_we   = 1;
                x4_we   = 1;
                x8_we   = 1;
                x12_we  = 1;
              end
            
            QR1:
              begin
                x1_we   = 1;
                x5_we   = 1;
                x9_we   = 1;
                x13_we  = 1;
              end
            
            QR2:
              begin
                x2_we   = 1;
                x6_we   = 1;
                x10_we  = 1;
                x14_we  = 1;
              end
            
            QR3:
              begin
                x3_we   = 1;
                x7_we   = 1;
                x11_we  = 1;
                x15_we  = 1;
              end
            
            QR4:
              begin
                x0_we   = 1;
                x5_we   = 1;
                x10_we  = 1;
                x15_we  = 1;
              end
            
            QR5:
              begin
                x1_we   = 1;
                x6_we   = 1;
                x11_we  = 1;
                x12_we  = 1;
              end
        
            QR6:
              begin
                x2_we   = 1;
                x7_we   = 1;
                x8_we   = 1;
                x13_we  = 1;
              end
            
            QR7:
              begin
                x3_we   = 1;
                x4_we   = 1;
                x9_we   = 1;
                x14_we  = 1;
              end
          endcase // case (quarterround_select)
        end // if (update_dp)
    end // state_update
  
  
  //----------------------------------------------------------------
  // qr_ctr
  // Update logic for the quarterround counter, a monotonically 
  // increasing counter with reset.
  //----------------------------------------------------------------
  always @*
    begin : qr_ctr
      // Defult assignments
      qr_ctr_new = 0;
      qr_ctr_we  = 0;
      
      if (qr_ctr_rst)
        begin
          qr_ctr_new = 0;
          qr_ctr_we  = 1;
        end

      if (qr_ctr_inc)
        begin
          qr_ctr_new = qr_ctr_reg + 1;
          qr_ctr_we  = 1;
        end
    end // qr_ctr
  
  
  //----------------------------------------------------------------
  // dr_ctr
  // Update logic for the round counter, a monotonically 
  // increasing counter with reset.
  //----------------------------------------------------------------
  always @*
    begin : dr_ctr
      // Defult assignments
      dr_ctr_new = 0;
      dr_ctr_we  = 0;
      
      if (dr_ctr_rst)
        begin
          dr_ctr_new = 0;
          dr_ctr_we  = 1;
        end

      if (dr_ctr_inc)
        begin
          dr_ctr_new = dr_ctr_reg + 1;
          dr_ctr_we  = 1;
        end
    end // dr_ctr
  
  
  //----------------------------------------------------------------
  // block_ctr
  // Update logic for the 64-bit block counter, a monotonically 
  // increasing counter with reset.
  //----------------------------------------------------------------
  always @*
    begin : block_ctr
      // Defult assignments
      block0_ctr_new = 32'h00000000;
      block1_ctr_new = 32'h00000000;
      block0_ctr_we = 0;
      block1_ctr_we = 0;
      
      if (block_ctr_rst)
        begin
          block0_ctr_we = 1;
          block1_ctr_we = 1;
        end
      
      if (block_ctr_inc)
        begin
          block0_ctr_new = block0_ctr_new + 1;
          block0_ctr_we = 1;

          // Avoid chaining the 32-bit adders.
          if (block0_ctr_reg == 32'hffffffff)
            begin
              block1_ctr_new = block1_ctr_new + 1;
              block1_ctr_we = 1;
            end
        end
    end // block_ctr
  

  //----------------------------------------------------------------
  // chacha_ctrl_fsm
  // Logic for the state machine controlling the core behaviour.
  //----------------------------------------------------------------
  always @*
    begin : chacha_ctrl_fsm
      // Default assignments
      init_cipher        = 0;
      init_round         = 0;
      update_dp          = 0;
      next_block         = 0;
      finalize           = 0;
                         
      qr_ctr_inc         = 0;
      qr_ctr_rst         = 0;
                         
      dr_ctr_inc         = 0;
      dr_ctr_rst         = 0;
                         
      block_ctr_inc      = 0;
      block_ctr_rst      = 0;
                         
      data_in_we         = 0;
      rounds_we          = 0;

      ready_wire         = 0;
      
      data_out_valid_new = 0;
      data_out_valid_we  = 0;
      
      chacha_ctrl_new    = CTRL_IDLE;
      chacha_ctrl_we     = 0;

      
      case (chacha_ctrl_reg)
        // Wait for init signal. When init is given
        // we initialize the datapath. Note that we
        // also assume that init implies start of
        // processing first block.
        CTRL_IDLE:
          begin
            ready_wire = 1;
            if (init)
              begin
                init_cipher     = 1;
                qr_ctr_rst      = 1;
                dr_ctr_rst      = 1;
                block_ctr_rst   = 1;
                data_in_we      = 1;
                rounds_we       = 1;
                chacha_ctrl_new = CTRL_ROUNDS;
                chacha_ctrl_we  = 1;
              end
          end

        // We perform 8 quarterrounds for each
        // double round and repeat until we have
        // processed the block. We then set data 
        // valid and move to CTR_DONE.
        CTRL_ROUNDS:
          begin
            update_dp  = 1;
            qr_ctr_inc = 1;
            if (qr_ctr_reg == QR7)
              begin
                dr_ctr_inc = 1;
                if (dr_ctr_reg == rounds_reg)
                  begin
                    data_out_valid_new = 1;
                    data_out_valid_we  = 1;
                    chacha_ctrl_new    = CTRL_DONE;
                    chacha_ctrl_we     = 1;
                  end
              end
          end

        // We wait for either next block signal or
        // init signal. When then drop valid, perform
        // initialization or 
        // either starts on a new block or 
        CTRL_DONE:
          begin
            ready_wire = 1;
            if (init)
              begin
                data_out_valid_new = 0;
                data_out_valid_we  = 1;
                init_cipher        = 1;
                qr_ctr_rst         = 1;
                dr_ctr_rst         = 1;
                block_ctr_rst      = 1;
                data_in_we         = 1;
                rounds_we          = 1;
                chacha_ctrl_new    = CTRL_ROUNDS;
                chacha_ctrl_we     = 1;
              end
            else if (next)
              begin
                init_round         = 1;
                data_out_valid_new = 0;
                data_out_valid_we  = 1;
                next_block         = 1;
                qr_ctr_rst         = 1;
                dr_ctr_rst         = 1;
                block_ctr_rst      = 1;
                data_in_we         = 1;
                rounds_we          = 1;
                chacha_ctrl_new    = CTRL_ROUNDS;
                chacha_ctrl_we     = 1;
              end
          end
      endcase // case (chacha_ctrl_reg)
    end // chacha_ctrl_fsm

endmodule // chacha_core

//======================================================================
// EOF chacha_core.v
//======================================================================
