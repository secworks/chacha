//======================================================================
//
// chacha_core.v
// --------------
// Verilog 2001 implementation of the stream cipher ChaCha.
// This is the internal core with wide interfaces.
//
// Note: data_in, state and data_out is treated as a 512 bit
// representation of a LSB vector of bytes. That is the LSB
// is stored in bits [511..
//
// Copyright (c) 2013 Secworks Sweden AB
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
                   input wire            clk,
                   input wire            reset_n,
                
                   input wire            init,
                   input wire            next,

                   input wire [255 : 0]  key,
                   input wire            keylen,
                   input wire [63 : 0]   iv,
                   input wire [4 : 0]    rounds,
                   
                   input wire [511 : 0]  data_in,
                   
                   output wire           ready,
                    
                   output wire [511 : 0] data_out,
                   output wire           data_out_valid
                  );

  
  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  // Datapath quartterround states names.
  parameter QR0 = 3'h0;
  parameter QR1 = 3'h1;
  parameter QR2 = 3'h2;
  parameter QR3 = 3'h3;
  parameter QR4 = 3'h4;
  parameter QR5 = 3'h5;
  parameter QR6 = 3'h6;
  parameter QR7 = 3'h7;

  parameter NUM_ROUNDS = 4'h8;

  parameter TAU0 = 32'h61707865;
  parameter TAU1 = 32'h3120646e;
  parameter TAU2 = 32'h79622d36;
  parameter TAU3 = 32'h6b206574;

  parameter SIGMA0 = 32'h61707865;
  parameter SIGMA1 = 32'h3320646e;
  parameter SIGMA2 = 32'h79622d32;
  parameter SIGMA3 = 32'h6b206574;
  
  parameter CTRL_IDLE     = 3'h0;
  parameter CTRL_INIT     = 3'h1;
  parameter CTRL_ROUNDS   = 3'h2;
  parameter CTRL_FINALIZE = 3'h3;
  parameter CTRL_DONE     = 3'h4;

  
  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg [31 : 0] key0_reg;
  reg [31 : 0] key1_reg;
  reg [31 : 0] key2_reg;
  reg [31 : 0] key3_reg;
  reg [31 : 0] key4_reg;
  reg [31 : 0] key5_reg;
  reg [31 : 0] key6_reg;
  reg [31 : 0] key7_reg;

  reg keylen_reg;
  
  reg [31 : 0] iv0_reg;
  reg [31 : 0] iv1_reg;

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
  
  reg  data_out_valid_reg;
  reg  data_out_valid_new;
  reg  data_out_valid_we;

  reg [2 : 0] qr_ctr_reg;
  reg [2 : 0] qr_ctr_new;
  reg         qr_ctr_we;
  reg         qr_ctr_inc;
  reg         qr_ctr_rst;
  
  reg [3 : 0] dr_ctr_reg;
  reg [3 : 0] dr_ctr_new;
  reg         dr_ctr_we;
  reg         dr_ctr_inc;
  reg         dr_ctr_rst;

  reg [31 : 0] block0_ctr_reg;
  reg [31 : 0] block0_ctr_new;
  reg          block0_ctr_we;
  reg [31 : 0] block1_ctr_reg;
  reg [31 : 0] block1_ctr_new;
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
  reg init_block;
  reg next_block;
  reg update_dp;
  reg update_state;
  reg init_state;
  reg sample_params;
  
  reg [31 : 0] qr0_a;
  reg [31 : 0] qr0_b;
  reg [31 : 0] qr0_c;
  reg [31 : 0] qr0_d;
  wire [31 : 0] qr0_a_prim;
  wire [31 : 0] qr0_b_prim;
  wire [31 : 0] qr0_c_prim;
  wire [31 : 0] qr0_d_prim;
  
  reg ready_wire;

  reg [511 : 0] tmp_data_out;


  //----------------------------------------------------------------
  // Instantiation of the qr module.
  //----------------------------------------------------------------
  chacha_qr qr0(
                .a(qr0_a),
                .b(qr0_b),
                .c(qr0_c),
                .d(qr0_d),
                
                .a_prim(qr0_a_prim),
                .b_prim(qr0_b_prim),
                .c_prim(qr0_c_prim),
                .d_prim(qr0_d_prim)
               );

  
  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign data_out = tmp_data_out;
  
  assign data_out_valid = data_out_valid_reg;
  
  assign ready = ready_wire;
  
  
  //----------------------------------------------------------------
  // reg_update
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with synchronous
  // active low reset. All registers have write enable.
  //----------------------------------------------------------------
  always @ (posedge clk)
    begin : reg_update
      if (!reset_n)
        begin
          key0_reg           <= 32'h00000000;
          key1_reg           <= 32'h00000000;
          key2_reg           <= 32'h00000000;
          key3_reg           <= 32'h00000000;
          key4_reg           <= 32'h00000000;
          key5_reg           <= 32'h00000000;
          key6_reg           <= 32'h00000000;
          key7_reg           <= 32'h00000000;
          iv0_reg            <= 32'h00000000;
          iv1_reg            <= 32'h00000000;
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
          if (sample_params)
            begin
              key0_reg   <= key[255 : 224];
              key1_reg   <= key[223 : 192];
              key2_reg   <= key[191 : 160];
              key3_reg   <= key[159 : 128];
              key4_reg   <= key[127 :  96];
              key5_reg   <= key[95  :  64];
              key6_reg   <= key[63  :  32];
              key7_reg   <= key[31  :   0];
              keylen_reg <= keylen;
              iv0_reg    <= iv[63  :  32];
              iv1_reg    <= iv[31  :   0];
              rounds_reg <= rounds[4 : 1];
            end

          if (data_in_we)
            begin
              data_in_reg <= data_in;
            end
          
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

          if (block0_ctr_we)
            begin
              block0_ctr_reg <= block0_ctr_new;
            end

          if (block1_ctr_we)
            begin
              block1_ctr_reg <= block1_ctr_new;
            end
          
          if (chacha_ctrl_we)
            begin
              chacha_ctrl_reg <= chacha_ctrl_new;
            end
        end
    end // reg_update

  
  //----------------------------------------------------------------
  // data_out_logic
  // Final output logic that combines the result from procceing
  // with the input word. This adds a final layer of XOR gates.
  // 
  // Note that we also remap all the words into LSB format.
  //----------------------------------------------------------------
  always @*
    begin : data_out_logic
      reg [31 : 0]  lsb_out0;
      reg [31 : 0]  lsb_out1;
      reg [31 : 0]  lsb_out2;
      reg [31 : 0]  lsb_out3;
      reg [31 : 0]  lsb_out4;
      reg [31 : 0]  lsb_out5;
      reg [31 : 0]  lsb_out6;
      reg [31 : 0]  lsb_out7;
      reg [31 : 0]  lsb_out8;
      reg [31 : 0]  lsb_out9;
      reg [31 : 0]  lsb_out10;
      reg [31 : 0]  lsb_out11;
      reg [31 : 0]  lsb_out12;
      reg [31 : 0]  lsb_out13;
      reg [31 : 0]  lsb_out14;
      reg [31 : 0]  lsb_out15;
      reg [511 : 0] msb_data_out;
      
      // NOTE: THIS IS HIGLY WRONG. Should be x_something
      msb_data_out = data_in_reg ^ data_in_reg;

      lsb_out0  = {msb_data_out[487 : 480], msb_data_out[495 : 488],
                   msb_data_out[503 : 496], msb_data_out[511 : 504]};
      
      lsb_out1 = {msb_data_out[455 : 448], msb_data_out[463 : 456], 
                  msb_data_out[471 : 464], msb_data_out[479 : 472]};
      
      lsb_out2 = {msb_data_out[423 : 416], msb_data_out[431 : 424], 
                  msb_data_out[439 : 432], msb_data_out[447 : 440]};
      
      lsb_out3 = {msb_data_out[391 : 384], msb_data_out[399 : 392], 
                  msb_data_out[407 : 400], msb_data_out[415 : 408]};
      
      lsb_out4 = {msb_data_out[359 : 352], msb_data_out[367 : 360], 
                  msb_data_out[375 : 368], msb_data_out[383 : 376]};
      
      lsb_out5 = {msb_data_out[327 : 320], msb_data_out[335 : 328], 
                  msb_data_out[343 : 336], msb_data_out[351 : 344]};
      
      lsb_out6 = {msb_data_out[295 : 288], msb_data_out[303 : 296], 
                  msb_data_out[311 : 304], msb_data_out[319 : 312]};
      
      lsb_out7 = {msb_data_out[263 : 256], msb_data_out[271 : 264], 
                  msb_data_out[279 : 272], msb_data_out[287 : 280]};
      
      lsb_out8 = {msb_data_out[231 : 224], msb_data_out[239 : 232], 
                  msb_data_out[247 : 240], msb_data_out[255 : 248]};
      
      lsb_out9 = {msb_data_out[199 : 192], msb_data_out[207 : 200], 
                  msb_data_out[215 : 208], msb_data_out[223 : 216]};
      
      lsb_out10 = {msb_data_out[167 : 160], msb_data_out[175 : 168], 
                   msb_data_out[183 : 176], msb_data_out[191 : 184]};
      
      lsb_out11 = {msb_data_out[135 : 128], msb_data_out[143 : 136], 
                   msb_data_out[151 : 144], msb_data_out[159 : 152]};

      lsb_out12 = {msb_data_out[103 :  96], msb_data_out[111 : 104],
                   msb_data_out[119 : 112], msb_data_out[127 : 120]};
      
      lsb_out13 = {msb_data_out[71 : 64], msb_data_out[79 : 72],
                    msb_data_out[87 : 80], msb_data_out[95 : 88]};
      
      lsb_out14 = {msb_data_out[39 : 32], msb_data_out[47 : 40],
                   msb_data_out[55 : 48], msb_data_out[63 : 56]};
      
      lsb_out15 = {msb_data_out[7  :  0], msb_data_out[15 :  8],
                   msb_data_out[23 : 16], msb_data_out[31 : 24]};

      tmp_data_out = {lsb_out0,  lsb_out1,  lsb_out2,  lsb_out3,
                      lsb_out4,  lsb_out5,  lsb_out6,  lsb_out7,
                      lsb_out8,  lsb_out9,  lsb_out10, lsb_out11,
                      lsb_out12, lsb_out13, lsb_out14, lsb_out15};
    end // data_out_logic

  
  //----------------------------------------------------------------
  // quarterround_mux
  // Quarterround muxes that selects operands for quarterrounds.
  //----------------------------------------------------------------
  always @*
    begin : quarterround_mux
      case (qr_ctr_reg)
          QR0:
            begin
              qr0_a = x0_reg;
              qr0_b = x4_reg;
              qr0_c = x8_reg;
              qr0_d = x12_reg;
            end
        
          QR1:
            begin
              qr0_a = x1_reg;
              qr0_b = x5_reg;
              qr0_c = x9_reg;
              qr0_d = x13_reg;
            end
        
          QR2:
            begin
              qr0_a = x2_reg;
              qr0_b = x6_reg;
              qr0_c = x10_reg;
              qr0_d = x14_reg;
            end
        
          QR3:
            begin
              qr0_a = x3_reg;
              qr0_b = x7_reg;
              qr0_c = x11_reg;
              qr0_d = x15_reg;
            end
        
          QR4:
            begin
              qr0_a = x0_reg;
              qr0_b = x5_reg;
              qr0_c = x10_reg;
              qr0_d = x15_reg;
            end
        
          QR5:
            begin
              qr0_a = x1_reg;
              qr0_b = x6_reg;
              qr0_c = x11_reg;
              qr0_d = x12_reg;
            end
        
          QR6:
            begin
              qr0_a = x2_reg;
              qr0_b = x7_reg;
              qr0_c = x8_reg;
              qr0_d = x13_reg;
            end
        
          QR7:
            begin
              qr0_a = x3_reg;
              qr0_b = x4_reg;
              qr0_c = x9_reg;
              qr0_d = x14_reg;
            end
      endcase // case (quarterround_select)
    end // quarterround_mux


  //----------------------------------------------------------------
  // state_update
  // Update the internal state by adding the new state with the old
  // state. We do this as 16 separate words.
  //----------------------------------------------------------------
  always @*
    begin : state_update
      reg [31 : 0] new_state_word0;
      reg [31 : 0] new_state_word1;
      reg [31 : 0] new_state_word2;
      reg [31 : 0] new_state_word3;
      reg [31 : 0] new_state_word4;
      reg [31 : 0] new_state_word5;
      reg [31 : 0] new_state_word6;
      reg [31 : 0] new_state_word7;
      reg [31 : 0] new_state_word8;
      reg [31 : 0] new_state_word9;
      reg [31 : 0] new_state_word10;
      reg [31 : 0] new_state_word11;
      reg [31 : 0] new_state_word12;
      reg [31 : 0] new_state_word13;
      reg [31 : 0] new_state_word14;
      reg [31 : 0] new_state_word15;

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
      
      if (init_state)
        begin
          new_state_word4  = {key[231 : 224], key[239 : 232], 
                              key[247 : 240], key[255 : 248]};
          new_state_word5  = {key[199 : 192], key[207 : 200], 
                              key[215 : 208], key[223 : 216]};
          new_state_word6  = {key[167 : 160], key[175 : 168], 
                              key[183 : 176], key[191 : 184]};
          new_state_word7  = {key[135 : 128], key[143 : 136], 
                              key[151 : 144], key[159 : 152]};

          new_state_word12 = block0_ctr_reg;
          new_state_word13 = block1_ctr_reg;
          
          new_state_word14 = {iv[39  :  32], iv[47  :  40],
                              iv[55  :  48], iv[63  :  56]};
          new_state_word15 = {iv[7   :   0], iv[15  :   8],
                              iv[23  :  16], iv[31  :  24]};

          if (keylen)
            begin
              // 256 bit key.
              new_state_word0  = SIGMA0;
              new_state_word1  = SIGMA1;
              new_state_word2  = SIGMA2;
              new_state_word3  = SIGMA3;
              new_state_word8  = {key[103 :  96], key[111 : 104],
                                  key[119 : 112], key[127 : 120]};
              new_state_word9  = {key[71  :  64], key[79  :  72],
                                  key[87  :  80], key[95  :  88]};
              new_state_word10 = {key[39  :  32], key[47  :  40],
                                  key[55  :  48], key[63  :  56]};
              new_state_word11 = {key[7   :   0], key[15  :   8],
                                  key[23  :  16], key[31  :  24]};
            end
          else
            begin
              // 128 bit key.
              new_state_word0  = TAU0;
              new_state_word1  = TAU1;
              new_state_word2  = TAU2;
              new_state_word3  = TAU3;
              new_state_word8  = {key[231 : 224], key[239 : 232], 
                                  key[247 : 240], key[255 : 248]};
              new_state_word9  = {key[199 : 192], key[207 : 200], 
                                  key[215 : 208], key[223 : 216]};
              new_state_word10  = {key[167 : 160], key[175 : 168], 
                                  key[183 : 176], key[191 : 184]};
              new_state_word11  = {key[135 : 128], key[143 : 136], 
                                  key[151 : 144], key[159 : 152]};
            end
          x0_we  = 1;
          x1_we  = 1;
          x2_we  = 1;
          x3_we  = 1;
          x4_we  = 1;
          x5_we  = 1;
          x6_we  = 1;
          x7_we  = 1;
          x8_we  = 1;
          x9_we  = 1;
          x10_we = 1;
          x11_we = 1;
          x12_we = 1;
          x13_we = 1;
          x14_we = 1;
          x15_we = 1;
          x0_new = new_state_word0;
          x1_new = new_state_word1;
          x2_new = new_state_word2;
          x3_new = new_state_word3;
          x4_new = new_state_word4;
          x5_new = new_state_word5;
          x6_new = new_state_word6;
          x7_new = new_state_word7;
          x8_new = new_state_word8;
          x9_new = new_state_word9;
          x10_new = new_state_word10;
          x11_new = new_state_word11;
          x12_new = new_state_word12;
          x13_new = new_state_word13;
          x14_new = new_state_word14;
          x15_new = new_state_word15;
        end // if (init_cipher)
      
      else if (update_dp)
        begin
          x0_new  = qr0_a_prim;
          x1_new  = qr0_a_prim; 
          x2_new  = qr0_a_prim;
          x3_new  = qr0_a_prim;

          x4_new  = qr0_b_prim;
          x5_new  = qr0_b_prim;
          x6_new  = qr0_b_prim;
          x7_new  = qr0_b_prim;

          x8_new  = qr0_c_prim;
          x9_new  = qr0_c_prim;
          x10_new = qr0_c_prim;
          x11_new = qr0_c_prim; 

          x12_new = qr0_d_prim;
          x13_new = qr0_d_prim;
          x14_new = qr0_d_prim;
          x15_new = qr0_d_prim;
          
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
          block0_ctr_new = block0_ctr_reg + 1;
          block0_ctr_we = 1;

          // Avoid chaining the 32-bit adders.
          if (block0_ctr_reg == 32'hffffffff)
            begin
              block1_ctr_new = block1_ctr_reg + 1;
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
      init_cipher        = 0;
      init_round         = 0;
      update_dp          = 0;
      init_block         = 0;
      next_block         = 0;
                         
      qr_ctr_inc         = 0;
      qr_ctr_rst         = 0;
                         
      dr_ctr_inc         = 0;
      dr_ctr_rst         = 0;
                         
      block_ctr_inc      = 0;
      block_ctr_rst      = 0;
                         
      data_in_we         = 0;

      ready_wire         = 0;
      
      data_out_valid_new = 0;
      data_out_valid_we  = 0;

      init_state         = 0;
      update_state       = 0;
      sample_params      = 0;
      
      chacha_ctrl_new    = CTRL_IDLE;
      chacha_ctrl_we     = 0;
      
      
      case (chacha_ctrl_reg)
        CTRL_IDLE:
          begin
            ready_wire = 1;
            if (init)
              begin
                sample_params   = 1;
                block_ctr_rst   = 1;
                chacha_ctrl_new = CTRL_INIT;
                chacha_ctrl_we  = 1;
              end
          end
        
        CTRL_INIT:
          begin
            data_in_we      = 1;
            qr_ctr_rst      = 1;
            dr_ctr_rst      = 1;
            init_state      = 1;
            chacha_ctrl_new = CTRL_ROUNDS;
            chacha_ctrl_we  = 1;
          end
        
        CTRL_ROUNDS:
          begin
            update_state = 1;
            qr_ctr_inc   = 1;
            if (qr_ctr_reg == QR7)
              begin
                dr_ctr_inc = 1;
                if (dr_ctr_reg == (rounds_reg - 1))
                  begin
                    chacha_ctrl_new = CTRL_FINALIZE;
                    chacha_ctrl_we  = 1;
                  end
              end
          end


        CTRL_FINALIZE:
          begin
            update_state       = 1;
            data_out_valid_new = 1;
            data_out_valid_we  = 1;
            chacha_ctrl_new    = CTRL_DONE;
            chacha_ctrl_we     = 1;
          end
        
        
        CTRL_DONE:
          begin
            ready_wire = 1;
            if (init)
              begin
                data_out_valid_new = 0;
                data_out_valid_we  = 1;
                sample_params      = 1;
                block_ctr_rst      = 1;
                chacha_ctrl_new    = CTRL_INIT;
                chacha_ctrl_we     = 1;
              end
            else if (next)
              begin
                data_out_valid_new = 0;
                data_out_valid_we  = 1;
                block_ctr_inc      = 1;
                chacha_ctrl_new    = CTRL_INIT;
                chacha_ctrl_we     = 1;
              end
          end
      endcase // case (chacha_ctrl_reg)
    end // chacha_ctrl_fsm
endmodule // chacha_core

//======================================================================
// EOF chacha_core.v
//======================================================================
