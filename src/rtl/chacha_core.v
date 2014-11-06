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
  parameter STATE_QR0 = 1'b0;
  parameter STATE_QR1 = 1'b1;

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
  reg [31 : 0] key0_new;
  reg [31 : 0] key1_reg;
  reg [31 : 0] key1_new;
  reg [31 : 0] key2_reg;
  reg [31 : 0] key2_new;
  reg [31 : 0] key3_reg;
  reg [31 : 0] key3_new;
  reg [31 : 0] key4_reg;
  reg [31 : 0] key4_new;
  reg [31 : 0] key5_reg;
  reg [31 : 0] key5_new;
  reg [31 : 0] key6_reg;
  reg [31 : 0] key6_new;
  reg [31 : 0] key7_reg;
  reg [31 : 0] key7_new;

  reg keylen_reg;
  reg keylen_new;

  reg [31 : 0] iv0_reg;
  reg [31 : 0] iv0_new;
  reg [31 : 0] iv1_reg;
  reg [31 : 0] iv1_new;

  reg [31 : 0] state0_reg;
  reg [31 : 0] state0_new;
  reg [31 : 0] state1_reg;
  reg [31 : 0] state1_new;
  reg [31 : 0] state2_reg;
  reg [31 : 0] state2_new;
  reg [31 : 0] state3_reg;
  reg [31 : 0] state3_new;
  reg [31 : 0] state4_reg;
  reg [31 : 0] state4_new;
  reg [31 : 0] state5_reg;
  reg [31 : 0] state5_new;
  reg [31 : 0] state6_reg;
  reg [31 : 0] state6_new;
  reg [31 : 0] state7_reg;
  reg [31 : 0] state7_new;
  reg [31 : 0] state8_reg;
  reg [31 : 0] state8_new;
  reg [31 : 0] state9_reg;
  reg [31 : 0] state9_new;
  reg [31 : 0] state10_reg;
  reg [31 : 0] state10_new;
  reg [31 : 0] state11_reg;
  reg [31 : 0] state11_new;
  reg [31 : 0] state12_reg;
  reg [31 : 0] state12_new;
  reg [31 : 0] state13_reg;
  reg [31 : 0] state13_new;
  reg [31 : 0] state14_reg;
  reg [31 : 0] state14_new;
  reg [31 : 0] state15_reg;
  reg [31 : 0] state15_new;
  reg state_we;

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

  reg [3 : 0] rounds_reg;
  reg [3 : 0] rounds_new;

  reg [511 : 0] data_in_reg;
  reg           data_in_we;

  reg [511 : 0] data_out_reg;
  reg [511 : 0] data_out_new;
  reg           data_out_we;

  reg  data_out_valid_reg;
  reg  data_out_valid_new;
  reg  data_out_valid_we;

  reg  ready_reg;
  reg  ready_new;
  reg  ready_we;

  reg         qr_ctr_reg;
  reg         qr_ctr_new;
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
  reg sample_params;
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
  always @ (posedge clk or negedge reset_n)
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
          state0_reg         <= 32'h00000000;
          state1_reg         <= 32'h00000000;
          state2_reg         <= 32'h00000000;
          state3_reg         <= 32'h00000000;
          state4_reg         <= 32'h00000000;
          state5_reg         <= 32'h00000000;
          state6_reg         <= 32'h00000000;
          state7_reg         <= 32'h00000000;
          state8_reg         <= 32'h00000000;
          state9_reg         <= 32'h00000000;
          state10_reg        <= 32'h00000000;
          state11_reg        <= 32'h00000000;
          state12_reg        <= 32'h00000000;
          state13_reg        <= 32'h00000000;
          state14_reg        <= 32'h00000000;
          state15_reg        <= 32'h00000000;
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
          data_out_reg       <= 512'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000;
          rounds_reg         <= 4'h0;
          ready_reg          <= 1;
          data_out_valid_reg <= 0;
          qr_ctr_reg         <= STATE_QR0;
          dr_ctr_reg         <= 0;
          block0_ctr_reg     <= 32'h00000000;
          block1_ctr_reg     <= 32'h00000000;
          chacha_ctrl_reg    <= CTRL_IDLE;
        end
      else
        begin
          if (sample_params)
            begin
              key0_reg   <= key0_new;
              key1_reg   <= key1_new;
              key2_reg   <= key2_new;
              key3_reg   <= key3_new;
              key4_reg   <= key4_new;
              key5_reg   <= key5_new;
              key6_reg   <= key6_new;
              key7_reg   <= key7_new;
              iv0_reg    <= iv0_new;
              iv1_reg    <= iv1_new;
              rounds_reg <= rounds_new;
              keylen_reg <= keylen_new;
            end

          if (data_in_we)
            begin
              data_in_reg <= data_in;
            end

          if (state_we)
            begin
              state0_reg  <= state0_new;
              state1_reg  <= state1_new;
              state2_reg  <= state2_new;
              state3_reg  <= state3_new;
              state4_reg  <= state4_new;
              state5_reg  <= state5_new;
              state6_reg  <= state6_new;
              state7_reg  <= state7_new;
              state8_reg  <= state8_new;
              state9_reg  <= state9_new;
              state10_reg <= state10_new;
              state11_reg <= state11_new;
              state12_reg <= state12_new;
              state13_reg <= state13_new;
              state14_reg <= state14_new;
              state15_reg <= state15_new;
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

          if (data_out_we)
            begin
              data_out_reg <= data_out_new;
            end

          if (ready_we)
            begin
              ready_reg <= ready_new;
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

      lsb_block_state = 512'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000;

      data_out_new = 512'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000;
      data_out_we = 0;

      if (update_output)
        begin
          msb_block_state0  = state0_reg  + x0_reg;
          msb_block_state1  = state1_reg  + x1_reg;
          msb_block_state2  = state2_reg  + x2_reg;
          msb_block_state3  = state3_reg  + x3_reg;
          msb_block_state4  = state4_reg  + x4_reg;
          msb_block_state5  = state5_reg  + x5_reg;
          msb_block_state6  = state6_reg  + x6_reg;
          msb_block_state7  = state7_reg  + x7_reg;
          msb_block_state8  = state8_reg  + x8_reg;
          msb_block_state9  = state9_reg  + x9_reg;
          msb_block_state10 = state10_reg + x10_reg;
          msb_block_state11 = state11_reg + x11_reg;
          msb_block_state12 = state12_reg + x12_reg;
          msb_block_state13 = state13_reg + x13_reg;
          msb_block_state14 = state14_reg + x14_reg;
          msb_block_state15 = state15_reg + x15_reg;

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

          data_out_new = data_in_reg ^ lsb_block_state;
          data_out_we   = 1;
        end // if (update_output)
    end // data_out_logic


  //----------------------------------------------------------------
  // sample_parameters
  // Logic (wires) that convert parameter input to appropriate
  // format for processing.
  //----------------------------------------------------------------
  always @*
    begin : sample_parameters
      key0_new   = 32'h00000000;
      key1_new   = 32'h00000000;
      key2_new   = 32'h00000000;
      key3_new   = 32'h00000000;
      key4_new   = 32'h00000000;
      key5_new   = 32'h00000000;
      key6_new   = 32'h00000000;
      key7_new   = 32'h00000000;
      iv0_new    = 32'h00000000;
      iv1_new    = 32'h00000000;
      rounds_new = 4'h0;
      keylen_new = 1'b0;

      if (sample_params)
        begin
          key0_new = {key[231 : 224], key[239 : 232],
                      key[247 : 240], key[255 : 248]};
          key1_new = {key[199 : 192], key[207 : 200],
                      key[215 : 208], key[223 : 216]};
          key2_new = {key[167 : 160], key[175 : 168],
                      key[183 : 176], key[191 : 184]};
          key3_new = {key[135 : 128], key[143 : 136],
                      key[151 : 144], key[159 : 152]};
          key4_new = {key[103 :  96], key[111 : 104],
                      key[119 : 112], key[127 : 120]};
          key5_new = {key[71  :  64], key[79  :  72],
                      key[87  :  80], key[95  :  88]};
          key6_new = {key[39  :  32], key[47  :  40],
                      key[55  :  48], key[63  :  56]};
          key7_new = {key[7   :   0], key[15  :   8],
                      key[23  :  16], key[31  :  24]};

          iv0_new = {iv[39  :  32], iv[47  :  40],
                     iv[55  :  48], iv[63  :  56]};
          iv1_new = {iv[7   :   0], iv[15  :   8],
                     iv[23  :  16], iv[31  :  24]};

          // Div by two since we count double rounds.
          rounds_new = rounds[4 : 1];

          keylen_new = keylen;
        end
    end


  //----------------------------------------------------------------
  // state_logic
  // Logic to init and update the internal state.
  //----------------------------------------------------------------
  always @*
    begin : state_logic
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

      new_state_word0  = 32'h00000000;
      new_state_word1  = 32'h00000000;
      new_state_word2  = 32'h00000000;
      new_state_word3  = 32'h00000000;
      new_state_word4  = 32'h00000000;
      new_state_word5  = 32'h00000000;
      new_state_word6  = 32'h00000000;
      new_state_word7  = 32'h00000000;
      new_state_word8  = 32'h00000000;
      new_state_word9  = 32'h00000000;
      new_state_word10 = 32'h00000000;
      new_state_word11 = 32'h00000000;
      new_state_word12 = 32'h00000000;
      new_state_word13 = 32'h00000000;
      new_state_word14 = 32'h00000000;
      new_state_word15 = 32'h00000000;

      x0_new  = 32'h00000000;
      x1_new  = 32'h00000000;
      x2_new  = 32'h00000000;
      x3_new  = 32'h00000000;
      x4_new  = 32'h00000000;
      x5_new  = 32'h00000000;
      x6_new  = 32'h00000000;
      x7_new  = 32'h00000000;
      x8_new  = 32'h00000000;
      x9_new  = 32'h00000000;
      x10_new = 32'h00000000;
      x11_new = 32'h00000000;
      x12_new = 32'h00000000;
      x13_new = 32'h00000000;
      x14_new = 32'h00000000;
      x15_new = 32'h00000000;
      x0_we   = 0;
      x1_we   = 0;
      x2_we   = 0;
      x3_we   = 0;
      x4_we   = 0;
      x5_we   = 0;
      x6_we   = 0;
      x7_we   = 0;
      x8_we   = 0;
      x9_we   = 0;
      x10_we  = 0;
      x11_we  = 0;
      x12_we  = 0;
      x13_we  = 0;
      x14_we  = 0;
      x15_we  = 0;

      state0_new  = 32'h00000000;
      state1_new  = 32'h00000000;
      state2_new  = 32'h00000000;
      state3_new  = 32'h00000000;
      state4_new  = 32'h00000000;
      state5_new  = 32'h00000000;
      state6_new  = 32'h00000000;
      state7_new  = 32'h00000000;
      state8_new  = 32'h00000000;
      state9_new  = 32'h00000000;
      state10_new = 32'h00000000;
      state11_new = 32'h00000000;
      state12_new = 32'h00000000;
      state13_new = 32'h00000000;
      state14_new = 32'h00000000;
      state15_new = 32'h00000000;
      state_we = 0;

      if (init_state)
        begin
          new_state_word4  = key0_reg;
          new_state_word5  = key1_reg;
          new_state_word6  = key2_reg;
          new_state_word7  = key3_reg;

          new_state_word12 = block0_ctr_reg;
          new_state_word13 = block1_ctr_reg;

          new_state_word14 = iv0_reg;
          new_state_word15 = iv1_reg;

          if (keylen_reg)
            begin
              // 256 bit key.
              new_state_word0  = SIGMA0;
              new_state_word1  = SIGMA1;
              new_state_word2  = SIGMA2;
              new_state_word3  = SIGMA3;
              new_state_word8  = key4_reg;
              new_state_word9  = key5_reg;
              new_state_word10 = key6_reg;
              new_state_word11 = key7_reg;
            end
          else
            begin
              // 128 bit key.
              new_state_word0  = TAU0;
              new_state_word1  = TAU1;
              new_state_word2  = TAU2;
              new_state_word3  = TAU3;
              new_state_word8  = key0_reg;
              new_state_word9  = key1_reg;
              new_state_word10 = key2_reg;
              new_state_word11 = key3_reg;
            end

          x0_new  = new_state_word0;
          x1_new  = new_state_word1;
          x2_new  = new_state_word2;
          x3_new  = new_state_word3;
          x4_new  = new_state_word4;
          x5_new  = new_state_word5;
          x6_new  = new_state_word6;
          x7_new  = new_state_word7;
          x8_new  = new_state_word8;
          x9_new  = new_state_word9;
          x10_new = new_state_word10;
          x11_new = new_state_word11;
          x12_new = new_state_word12;
          x13_new = new_state_word13;
          x14_new = new_state_word14;
          x15_new = new_state_word15;
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

          state0_new  = new_state_word0;
          state1_new  = new_state_word1;
          state2_new  = new_state_word2;
          state3_new  = new_state_word3;
          state4_new  = new_state_word4;
          state5_new  = new_state_word5;
          state6_new  = new_state_word6;
          state7_new  = new_state_word7;
          state8_new  = new_state_word8;
          state9_new  = new_state_word9;
          state10_new = new_state_word10;
          state11_new = new_state_word11;
          state12_new = new_state_word12;
          state13_new = new_state_word13;
          state14_new = new_state_word14;
          state15_new = new_state_word15;
          state_we = 1;
        end // if (init_state)

      else if (update_state)
        begin
          case (qr_ctr_reg)
            STATE_QR0:
              begin
                x0_new  = qr0_a_prim;
                x4_new  = qr0_b_prim;
                x8_new  = qr0_c_prim;
                x12_new = qr0_d_prim;
                x0_we   = 1;
                x4_we   = 1;
                x8_we   = 1;
                x12_we  = 1;

                x1_new  = qr1_a_prim;
                x5_new  = qr1_b_prim;
                x9_new  = qr1_c_prim;
                x13_new = qr1_d_prim;
                x1_we   = 1;
                x5_we   = 1;
                x9_we   = 1;
                x13_we  = 1;

                x2_new  = qr2_a_prim;
                x6_new  = qr2_b_prim;
                x10_new = qr2_c_prim;
                x14_new = qr2_d_prim;
                x2_we   = 1;
                x6_we   = 1;
                x10_we  = 1;
                x14_we  = 1;

                x3_new  = qr3_a_prim;
                x7_new  = qr3_b_prim;
                x11_new = qr3_c_prim;
                x15_new = qr3_d_prim;
                x3_we   = 1;
                x7_we   = 1;
                x11_we  = 1;
                x15_we  = 1;
              end

            STATE_QR1:
              begin
                x0_new  = qr0_a_prim;
                x5_new  = qr0_b_prim;
                x10_new = qr0_c_prim;
                x15_new = qr0_d_prim;
                x0_we   = 1;
                x5_we   = 1;
                x10_we  = 1;
                x15_we  = 1;

                x1_new  = qr1_a_prim;
                x6_new  = qr1_b_prim;
                x11_new = qr1_c_prim;
                x12_new = qr1_d_prim;
                x1_we   = 1;
                x6_we   = 1;
                x11_we  = 1;
                x12_we  = 1;

                x2_new  = qr2_a_prim;
                x7_new  = qr2_b_prim;
                x8_new  = qr2_c_prim;
                x13_new = qr2_d_prim;
                x2_we   = 1;
                x7_we   = 1;
                x8_we   = 1;
                x13_we  = 1;

                x3_new  = qr3_a_prim;
                x4_new  = qr3_b_prim;
                x9_new  = qr3_c_prim;
                x14_new = qr3_d_prim;
                x3_we   = 1;
                x4_we   = 1;
                x9_we   = 1;
                x14_we  = 1;
              end
          endcase // case (quarterround_select)
        end // if (update_state)
    end // state_logic


  //----------------------------------------------------------------
  // quarterround_mux
  // Quarterround muxes that selects operands for quarterrounds.
  //----------------------------------------------------------------
  always @*
    begin : quarterround_mux
      case (qr_ctr_reg)
          STATE_QR0:
            begin
              qr0_a = x0_reg;
              qr0_b = x4_reg;
              qr0_c = x8_reg;
              qr0_d = x12_reg;

              qr1_a = x1_reg;
              qr1_b = x5_reg;
              qr1_c = x9_reg;
              qr1_d = x13_reg;

              qr2_a = x2_reg;
              qr2_b = x6_reg;
              qr2_c = x10_reg;
              qr2_d = x14_reg;

              qr3_a = x3_reg;
              qr3_b = x7_reg;
              qr3_c = x11_reg;
              qr3_d = x15_reg;
            end

          STATE_QR1:
            begin
              qr0_a = x0_reg;
              qr0_b = x5_reg;
              qr0_c = x10_reg;
              qr0_d = x15_reg;

              qr1_a = x1_reg;
              qr1_b = x6_reg;
              qr1_c = x11_reg;
              qr1_d = x12_reg;

              qr2_a = x2_reg;
              qr2_b = x7_reg;
              qr2_c = x8_reg;
              qr2_d = x13_reg;

              qr3_a = x3_reg;
              qr3_b = x4_reg;
              qr3_c = x9_reg;
              qr3_d = x14_reg;
            end
      endcase // case (quarterround_select)
    end // quarterround_mux


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
      // Defult assignments
      block0_ctr_new = 32'h00000000;
      block1_ctr_new = 32'h00000000;
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
      sample_params      = 0;
      update_output      = 0;

      qr_ctr_inc         = 0;
      qr_ctr_rst         = 0;

      dr_ctr_inc         = 0;
      dr_ctr_rst         = 0;

      block_ctr_inc      = 0;
      block_ctr_rst      = 0;

      data_in_we         = 0;

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
                ready_new       = 0;
                ready_we        = 1;
                data_in_we      = 1;
                sample_params   = 1;
                block_ctr_rst   = 1;
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
            if (qr_ctr_reg == STATE_QR1)
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
                data_in_we         = 1;
                sample_params      = 1;
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
                data_in_we         = 1;
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
