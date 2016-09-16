//======================================================================
//
// chacha_core.v
// --------------
// Verilog 2001 implementation of the stream cipher ChaCha.
// This is the internal core with wide interfaces.
//
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
                   input wire [63 : 0]   ctr,
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
  reg [31 : 0] state_reg [0 : 15];
  reg [31 : 0] state_new [0 : 15];
  reg          state_we;

  reg [511 : 0] data_out_reg;
  reg [511 : 0] data_out_new;
  reg           data_out_we;

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

  reg          ready_reg;
  reg          ready_new;
  reg          ready_we;

  reg [2 : 0] chacha_ctrl_reg;
  reg [2 : 0] chacha_ctrl_new;
  reg         chacha_ctrl_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [31 : 0] init_state_word0;
  reg [31 : 0] init_state_word1;
  reg [31 : 0] init_state_word2;
  reg [31 : 0] init_state_word3;
  reg [31 : 0] init_state_word4;
  reg [31 : 0] init_state_word5;
  reg [31 : 0] init_state_word6;
  reg [31 : 0] init_state_word7;
  reg [31 : 0] init_state_word8;
  reg [31 : 0] init_state_word9;
  reg [31 : 0] init_state_word10;
  reg [31 : 0] init_state_word11;
  reg [31 : 0] init_state_word12;
  reg [31 : 0] init_state_word13;
  reg [31 : 0] init_state_word14;
  reg [31 : 0] init_state_word15;

  reg init_state;
  reg update_state;
  reg update_output;

  reg [31 : 0]  qr0_a;
  reg [31 : 0]  qr0_b;
  reg [31 : 0]  qr0_c;
  reg [31 : 0]  qr0_d;
  wire [31 : 0] qr0_a_prim;
  wire [31 : 0] qr0_b_prim;
  wire [31 : 0] qr0_c_prim;
  wire [31 : 0] qr0_d_prim;

  reg [31 : 0]  qr1_a;
  reg [31 : 0]  qr1_b;
  reg [31 : 0]  qr1_c;
  reg [31 : 0]  qr1_d;
  wire [31 : 0] qr1_a_prim;
  wire [31 : 0] qr1_b_prim;
  wire [31 : 0] qr1_c_prim;
  wire [31 : 0] qr1_d_prim;

  reg [31 : 0]  qr2_a;
  reg [31 : 0]  qr2_b;
  reg [31 : 0]  qr2_c;
  reg [31 : 0]  qr2_d;
  wire [31 : 0] qr2_a_prim;
  wire [31 : 0] qr2_b_prim;
  wire [31 : 0] qr2_c_prim;
  wire [31 : 0] qr2_d_prim;

  reg [31 : 0]  qr3_a;
  reg [31 : 0]  qr3_b;
  reg [31 : 0]  qr3_c;
  reg [31 : 0]  qr3_d;
  wire [31 : 0] qr3_a_prim;
  wire [31 : 0] qr3_b_prim;
  wire [31 : 0] qr3_c_prim;
  wire [31 : 0] qr3_d_prim;


  //----------------------------------------------------------------
  // Instantiation of the qr modules.
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

  chacha_qr qr1(
                .a(qr1_a),
                .b(qr1_b),
                .c(qr1_c),
                .d(qr1_d),

                .a_prim(qr1_a_prim),
                .b_prim(qr1_b_prim),
                .c_prim(qr1_c_prim),
                .d_prim(qr1_d_prim)
               );

  chacha_qr qr2(
                .a(qr2_a),
                .b(qr2_b),
                .c(qr2_c),
                .d(qr2_d),

                .a_prim(qr2_a_prim),
                .b_prim(qr2_b_prim),
                .c_prim(qr2_c_prim),
                .d_prim(qr2_d_prim)
               );

  chacha_qr qr3(
                .a(qr3_a),
                .b(qr3_b),
                .c(qr3_c),
                .d(qr3_d),

                .a_prim(qr3_a_prim),
                .b_prim(qr3_b_prim),
                .c_prim(qr3_c_prim),
                .d_prim(qr3_d_prim)
               );


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign data_out = data_out_reg;
  assign data_out_valid = data_out_valid_reg;
  assign ready = ready_reg;


  //----------------------------------------------------------------
  // reg_update
  //
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with asynchronous
  // active low reset. All registers have write enable.
  //----------------------------------------------------------------
  always @ (posedge clk)
    begin : reg_update
     integer i;

      if (!reset_n)
        begin
          for (i = 0 ; i < 16 ; i = i + 1)
            state_reg[i] <= 32'h0;

          data_out_reg       <= 512'h0;
          data_out_valid_reg <= 0;
          qr_ctr_reg         <= QR0;
          dr_ctr_reg         <= 0;
          block0_ctr_reg     <= 32'h0;
          block1_ctr_reg     <= 32'h0;
          chacha_ctrl_reg    <= CTRL_IDLE;
          ready_reg          <= 1;
        end
      else
        begin
          if (state_we)
            begin
              for (i = 0 ; i < 16 ; i = i + 1)
                state_reg[i] <= state_new[i];
            end

          if (data_out_we)
            data_out_reg <= data_out_new;

          if (data_out_valid_we)
            data_out_valid_reg <= data_out_valid_new;

          if (qr_ctr_we)
            qr_ctr_reg <= qr_ctr_new;

          if (dr_ctr_we)
            dr_ctr_reg <= dr_ctr_new;

          if (block0_ctr_we)
            block0_ctr_reg <= block0_ctr_new;

          if (block1_ctr_we)
            block1_ctr_reg <= block1_ctr_new;

          if (ready_we)
            ready_reg <= ready_new;

          if (chacha_ctrl_we)
            chacha_ctrl_reg <= chacha_ctrl_new;
        end
    end // reg_update


  //----------------------------------------------------------------
  // init_state_logic
  //
  // Calculates the initial state for a given block.
  //----------------------------------------------------------------
  always @*
    begin : init_state_logic
      reg [31 : 0] key0;
      reg [31 : 0] key1;
      reg [31 : 0] key2;
      reg [31 : 0] key3;
      reg [31 : 0] key4;
      reg [31 : 0] key5;
      reg [31 : 0] key6;
      reg [31 : 0] key7;

      key0 = {key[231 : 224], key[239 : 232],
              key[247 : 240], key[255 : 248]};
      key1 = {key[199 : 192], key[207 : 200],
              key[215 : 208], key[223 : 216]};
      key2 = {key[167 : 160], key[175 : 168],
              key[183 : 176], key[191 : 184]};
      key3 = {key[135 : 128], key[143 : 136],
              key[151 : 144], key[159 : 152]};
      key4 = {key[103 :  96], key[111 : 104],
              key[119 : 112], key[127 : 120]};
      key5 = {key[71  :  64], key[79  :  72],
              key[87  :  80], key[95  :  88]};
      key6 = {key[39  :  32], key[47  :  40],
              key[55  :  48], key[63  :  56]};
      key7 = {key[7   :   0], key[15  :   8],
              key[23  :  16], key[31  :  24]};

      init_state_word4  = key0;
      init_state_word5  = key1;
      init_state_word6  = key2;
      init_state_word7  = key3;
      init_state_word12 = block0_ctr_reg;
      init_state_word13 = block1_ctr_reg;
      init_state_word14 = {iv[39  :  32], iv[47  :  40],
                          iv[55  :  48], iv[63  :  56]};
      init_state_word15 = {iv[7   :   0], iv[15  :   8],
                          iv[23  :  16], iv[31  :  24]};

      if (keylen)
        begin
          // 256 bit key.
          init_state_word0  = SIGMA0;
          init_state_word1  = SIGMA1;
          init_state_word2  = SIGMA2;
          init_state_word3  = SIGMA3;
          init_state_word8  = key4;
          init_state_word9  = key5;
          init_state_word10 = key6;
          init_state_word11 = key7;
        end
      else
        begin
          // 128 bit key.
          init_state_word0  = TAU0;
          init_state_word1  = TAU1;
          init_state_word2  = TAU2;
          init_state_word3  = TAU3;
          init_state_word8  = key0;
          init_state_word9  = key1;
          init_state_word10 = key2;
          init_state_word11 = key3;
        end
    end


  //----------------------------------------------------------------
  // state_logic
  // Logic to init and update the internal state.
  //----------------------------------------------------------------
  always @*
    begin : state_logic
      state_we    = 0;

      if (init_state)
        begin
          state_new[00] = init_state_word0;
          state_new[01] = init_state_word1;
          state_new[02] = init_state_word2;
          state_new[03] = init_state_word3;
          state_new[04] = init_state_word4;
          state_new[05] = init_state_word5;
          state_new[06] = init_state_word6;
          state_new[07] = init_state_word7;
          state_new[08] = init_state_word8;
          state_new[09] = init_state_word9;
          state_new[10] = init_state_word10;
          state_new[11] = init_state_word11;
          state_new[12] = init_state_word12;
          state_new[13] = init_state_word13;
          state_new[14] = init_state_word14;
          state_new[15] = init_state_word15;
          state_we   = 1;
        end // if (init_state)

      if (update_state)
        begin
          state_we = 1;
          case (qr_ctr_reg)
            QR0:
              begin
                qr0_a = state_reg[00];
                qr0_b = state_reg[04];
                qr0_c = state_reg[08];
                qr0_d = state_reg[12];
                qr1_a = state_reg[01];
                qr1_b = state_reg[05];
                qr1_c = state_reg[09];
                qr1_d = state_reg[13];
                qr2_a = state_reg[02];
                qr2_b = state_reg[06];
                qr2_c = state_reg[10];
                qr2_d = state_reg[14];
                qr3_a = state_reg[03];
                qr3_b = state_reg[07];
                qr3_c = state_reg[11];
                qr3_d = state_reg[15];
                state_new[00] = qr0_a_prim;
                state_new[04] = qr0_b_prim;
                state_new[08] = qr0_c_prim;
                state_new[12] = qr0_d_prim;
                state_new[01] = qr1_a_prim;
                state_new[05] = qr1_b_prim;
                state_new[09] = qr1_c_prim;
                state_new[13] = qr1_d_prim;
                state_new[02] = qr2_a_prim;
                state_new[06] = qr2_b_prim;
                state_new[10] = qr2_c_prim;
                state_new[14] = qr2_d_prim;
                state_new[03] = qr3_a_prim;
                state_new[07] = qr3_b_prim;
                state_new[11] = qr3_c_prim;
                state_new[15] = qr3_d_prim;
              end

            QR1:
              begin
                qr0_a = state_reg[00];
                qr0_b = state_reg[05];
                qr0_c = state_reg[10];
                qr0_d = state_reg[15];
                qr1_a = state_reg[01];
                qr1_b = state_reg[06];
                qr1_c = state_reg[11];
                qr1_d = state_reg[12];
                qr2_a = state_reg[02];
                qr2_b = state_reg[07];
                qr2_c = state_reg[08];
                qr2_d = state_reg[13];
                qr3_a = state_reg[03];
                qr3_b = state_reg[04];
                qr3_c = state_reg[09];
                qr3_d = state_reg[14];
                state_new[00] = qr0_a_prim;
                state_new[05] = qr0_b_prim;
                state_new[10] = qr0_c_prim;
                state_new[15] = qr0_d_prim;
                state_new[01] = qr1_a_prim;
                state_new[06] = qr1_b_prim;
                state_new[11] = qr1_c_prim;
                state_new[12] = qr1_d_prim;
                state_new[02] = qr2_a_prim;
                state_new[07] = qr2_b_prim;
                state_new[08] = qr2_c_prim;
                state_new[13] = qr2_d_prim;
                state_new[03] = qr3_a_prim;
                state_new[04] = qr3_b_prim;
                state_new[09] = qr3_c_prim;
                state_new[14] = qr3_d_prim;
              end
          endcase // case (quarterround_select)
        end // if (update_state)
    end // state_logic


  //----------------------------------------------------------------
  // data_out_logic
  // Final output logic that combines the result from procceing
  // with the input word. This adds a final layer of XOR gates.
  //
  // Note that we also remap all the words into LSB format.
  //----------------------------------------------------------------
  always @*
    begin : data_out_logic
      reg [31 : 0]  msb_block_state0;
      reg [31 : 0]  msb_block_state1;
      reg [31 : 0]  msb_block_state2;
      reg [31 : 0]  msb_block_state3;
      reg [31 : 0]  msb_block_state4;
      reg [31 : 0]  msb_block_state5;
      reg [31 : 0]  msb_block_state6;
      reg [31 : 0]  msb_block_state7;
      reg [31 : 0]  msb_block_state8;
      reg [31 : 0]  msb_block_state9;
      reg [31 : 0]  msb_block_state10;
      reg [31 : 0]  msb_block_state11;
      reg [31 : 0]  msb_block_state12;
      reg [31 : 0]  msb_block_state13;
      reg [31 : 0]  msb_block_state14;
      reg [31 : 0]  msb_block_state15;

      reg [31 : 0]  lsb_block_state0;
      reg [31 : 0]  lsb_block_state1;
      reg [31 : 0]  lsb_block_state2;
      reg [31 : 0]  lsb_block_state3;
      reg [31 : 0]  lsb_block_state4;
      reg [31 : 0]  lsb_block_state5;
      reg [31 : 0]  lsb_block_state6;
      reg [31 : 0]  lsb_block_state7;
      reg [31 : 0]  lsb_block_state8;
      reg [31 : 0]  lsb_block_state9;
      reg [31 : 0]  lsb_block_state10;
      reg [31 : 0]  lsb_block_state11;
      reg [31 : 0]  lsb_block_state12;
      reg [31 : 0]  lsb_block_state13;
      reg [31 : 0]  lsb_block_state14;
      reg [31 : 0]  lsb_block_state15;

      reg [511 : 0] lsb_block_state;

      lsb_block_state = 512'h0;
      data_out_new = 512'h0;
      data_out_we = 0;

      if (update_output)
        begin
          msb_block_state0  = init_state_word0  + state_reg[00];
          msb_block_state1  = init_state_word1  + state_reg[01];
          msb_block_state2  = init_state_word2  + state_reg[02];
          msb_block_state3  = init_state_word3  + state_reg[03];
          msb_block_state4  = init_state_word4  + state_reg[04];
          msb_block_state5  = init_state_word5  + state_reg[05];
          msb_block_state6  = init_state_word6  + state_reg[06];
          msb_block_state7  = init_state_word7  + state_reg[07];
          msb_block_state8  = init_state_word8  + state_reg[08];
          msb_block_state9  = init_state_word9  + state_reg[09];
          msb_block_state10 = init_state_word10 + state_reg[10];
          msb_block_state11 = init_state_word11 + state_reg[11];
          msb_block_state12 = init_state_word12 + state_reg[12];
          msb_block_state13 = init_state_word13 + state_reg[13];
          msb_block_state14 = init_state_word14 + state_reg[14];
          msb_block_state15 = init_state_word15 + state_reg[15];

          lsb_block_state0 = {msb_block_state0[7  :  0],
                              msb_block_state0[15 :  8],
                              msb_block_state0[23 : 16],
                              msb_block_state0[31 : 24]};

          lsb_block_state1 = {msb_block_state1[7  :  0],
                              msb_block_state1[15 :  8],
                              msb_block_state1[23 : 16],
                              msb_block_state1[31 : 24]};

          lsb_block_state2 = {msb_block_state2[7  :  0],
                              msb_block_state2[15 :  8],
                              msb_block_state2[23 : 16],
                              msb_block_state2[31 : 24]};

          lsb_block_state3 = {msb_block_state3[7  :  0],
                              msb_block_state3[15 :  8],
                              msb_block_state3[23 : 16],
                              msb_block_state3[31 : 24]};

          lsb_block_state4 = {msb_block_state4[7  :  0],
                              msb_block_state4[15 :  8],
                              msb_block_state4[23 : 16],
                              msb_block_state4[31 : 24]};

          lsb_block_state5 = {msb_block_state5[7  :  0],
                              msb_block_state5[15 :  8],
                              msb_block_state5[23 : 16],
                              msb_block_state5[31 : 24]};

          lsb_block_state6 = {msb_block_state6[7  :  0],
                              msb_block_state6[15 :  8],
                              msb_block_state6[23 : 16],
                              msb_block_state6[31 : 24]};

          lsb_block_state7 = {msb_block_state7[7  :  0],
                              msb_block_state7[15 :  8],
                              msb_block_state7[23 : 16],
                              msb_block_state7[31 : 24]};

          lsb_block_state8 = {msb_block_state8[7  :  0],
                              msb_block_state8[15 :  8],
                              msb_block_state8[23 : 16],
                              msb_block_state8[31 : 24]};

          lsb_block_state9 = {msb_block_state9[7  :  0],
                              msb_block_state9[15 :  8],
                              msb_block_state9[23 : 16],
                              msb_block_state9[31 : 24]};

          lsb_block_state10 = {msb_block_state10[7  :  0],
                               msb_block_state10[15 :  8],
                               msb_block_state10[23 : 16],
                               msb_block_state10[31 : 24]};

          lsb_block_state11 = {msb_block_state11[7  :  0],
                               msb_block_state11[15 :  8],
                               msb_block_state11[23 : 16],
                               msb_block_state11[31 : 24]};

          lsb_block_state12 = {msb_block_state12[7  :  0],
                               msb_block_state12[15 :  8],
                               msb_block_state12[23 : 16],
                               msb_block_state12[31 : 24]};

          lsb_block_state13 = {msb_block_state13[7  :  0],
                               msb_block_state13[15 :  8],
                               msb_block_state13[23 : 16],
                               msb_block_state13[31 : 24]};

          lsb_block_state14 = {msb_block_state14[7  :  0],
                               msb_block_state14[15 :  8],
                               msb_block_state14[23 : 16],
                               msb_block_state14[31 : 24]};

          lsb_block_state15 = {msb_block_state15[7  :  0],
                               msb_block_state15[15 :  8],
                               msb_block_state15[23 : 16],
                               msb_block_state15[31 : 24]};

          lsb_block_state = {lsb_block_state0,  lsb_block_state1,
                             lsb_block_state2,  lsb_block_state3,
                             lsb_block_state4,  lsb_block_state5,
                             lsb_block_state6,  lsb_block_state7,
                             lsb_block_state8,  lsb_block_state9,
                             lsb_block_state10, lsb_block_state11,
                             lsb_block_state12, lsb_block_state13,
                             lsb_block_state14, lsb_block_state15};

          data_out_new = data_in ^ lsb_block_state;
          data_out_we   = 1;
        end // if (update_output)
    end // data_out_logic


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
          qr_ctr_new = qr_ctr_reg + 1'b1;
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
          dr_ctr_new = dr_ctr_reg + 1'b1;
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
      block0_ctr_new = 32'h0;
      block1_ctr_new = 32'h0;
      block0_ctr_we = 0;
      block1_ctr_we = 0;

      if (block_ctr_rst)
        begin
          block0_ctr_new = ctr[31 : 00];
          block1_ctr_new = ctr[63 : 32];
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
      init_state         = 0;
      update_state       = 0;
      update_output      = 0;
      qr_ctr_inc         = 0;
      qr_ctr_rst         = 0;
      dr_ctr_inc         = 0;
      dr_ctr_rst         = 0;
      block_ctr_inc      = 0;
      block_ctr_rst      = 0;
      ready_new          = 0;
      ready_we           = 0;
      data_out_valid_new = 0;
      data_out_valid_we  = 0;
      chacha_ctrl_new    = CTRL_IDLE;
      chacha_ctrl_we     = 0;

      case (chacha_ctrl_reg)
        CTRL_IDLE:
          begin
            if (init)
              begin
                block_ctr_rst   = 1;
                ready_new       = 0;
                ready_we        = 1;
                chacha_ctrl_new = CTRL_INIT;
                chacha_ctrl_we  = 1;
              end
          end

        CTRL_INIT:
          begin
            init_state      = 1;
            qr_ctr_rst      = 1;
            dr_ctr_rst      = 1;
            chacha_ctrl_new = CTRL_ROUNDS;
            chacha_ctrl_we  = 1;
          end

        CTRL_ROUNDS:
          begin
            update_state = 1;
            qr_ctr_inc   = 1;
            if (qr_ctr_reg == QR1)
              begin
                dr_ctr_inc = 1;
                if (dr_ctr_reg == (rounds[4 : 1] - 1))
                  begin
                    chacha_ctrl_new = CTRL_FINALIZE;
                    chacha_ctrl_we  = 1;
                  end
              end
          end

        CTRL_FINALIZE:
          begin
            ready_new          = 1;
            ready_we           = 1;
            update_output      = 1;
            data_out_valid_new = 1;
            data_out_valid_we  = 1;
            chacha_ctrl_new    = CTRL_DONE;
            chacha_ctrl_we     = 1;
          end

        CTRL_DONE:
          begin
            if (init)
              begin
                ready_new          = 0;
                ready_we           = 1;
                data_out_valid_new = 0;
                data_out_valid_we  = 1;
                block_ctr_rst      = 1;
                chacha_ctrl_new    = CTRL_INIT;
                chacha_ctrl_we     = 1;
              end
            else if (next)
              begin
                ready_new          = 0;
                ready_we           = 1;
                data_out_valid_new = 0;
                data_out_valid_we  = 1;
                block_ctr_inc      = 1;
                chacha_ctrl_new    = CTRL_INIT;
                chacha_ctrl_we     = 1;
              end
          end

        default:
          begin

          end
      endcase // case (chacha_ctrl_reg)
    end // chacha_ctrl_fsm
endmodule // chacha_core

//======================================================================
// EOF chacha_core.v
//======================================================================
