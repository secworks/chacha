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
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg init_reg;
  reg next_reg;
  reg ctrl_we;

  reg ready_reg;

  reg keylen_reg;
  reg keylen_we;

  reg [4 : 0] rounds_reg;
  reg         rounds_we;

  reg data_out_valid_reg;

  reg [31 : 0] key_reg [0 : 7];
  reg          key_we;

  reg [31 : 0] iv0_reg;
  reg          iv0_we;
  reg [31 : 0] iv1_reg;
  reg          iv1_we;

  reg [31 : 0] data_in0_reg;
  reg          data_in0_we;
  reg [31 : 0] data_in1_reg;
  reg          data_in1_we;
  reg [31 : 0] data_in2_reg;
  reg          data_in2_we;
  reg [31 : 0] data_in3_reg;
  reg          data_in3_we;
  reg [31 : 0] data_in4_reg;
  reg          data_in4_we;
  reg [31 : 0] data_in5_reg;
  reg          data_in5_we;
  reg [31 : 0] data_in6_reg;
  reg          data_in6_we;
  reg [31 : 0] data_in7_reg;
  reg          data_in7_we;
  reg [31 : 0] data_in8_reg;
  reg          data_in8_we;
  reg [31 : 0] data_in9_reg;
  reg          data_in9_we;
  reg [31 : 0] data_in10_reg;
  reg          data_in10_we;
  reg [31 : 0] data_in11_reg;
  reg          data_in11_we;
  reg [31 : 0] data_in12_reg;
  reg          data_in12_we;
  reg [31 : 0] data_in13_reg;
  reg          data_in13_we;
  reg [31 : 0] data_in14_reg;
  reg          data_in14_we;
  reg [31 : 0] data_in15_reg;
  reg          data_in15_we;

  reg [31 : 0] data_out0_reg;
  reg [31 : 0] data_out0_new;
  reg [31 : 0] data_out1_reg;
  reg [31 : 0] data_out1_new;
  reg [31 : 0] data_out2_reg;
  reg [31 : 0] data_out2_new;
  reg [31 : 0] data_out3_reg;
  reg [31 : 0] data_out3_new;
  reg [31 : 0] data_out4_reg;
  reg [31 : 0] data_out4_new;
  reg [31 : 0] data_out5_reg;
  reg [31 : 0] data_out5_new;
  reg [31 : 0] data_out6_reg;
  reg [31 : 0] data_out6_new;
  reg [31 : 0] data_out7_reg;
  reg [31 : 0] data_out7_new;
  reg [31 : 0] data_out8_reg;
  reg [31 : 0] data_out8_new;
  reg [31 : 0] data_out9_reg;
  reg [31 : 0] data_out9_new;
  reg [31 : 0] data_out10_reg;
  reg [31 : 0] data_out10_new;
  reg [31 : 0] data_out11_reg;
  reg [31 : 0] data_out11_new;
  reg [31 : 0] data_out12_reg;
  reg [31 : 0] data_out12_new;
  reg [31 : 0] data_out13_reg;
  reg [31 : 0] data_out13_new;
  reg [31 : 0] data_out14_reg;
  reg [31 : 0] data_out14_new;
  reg [31 : 0] data_out15_reg;
  reg [31 : 0] data_out15_new;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  wire           core_init;
  wire           core_next;
  wire [255 : 0] core_key;
  wire           core_keylen;
  wire [4 : 0]   core_rounds;
  wire [63 : 0]  core_iv;
  wire           core_ready;
  wire [511 : 0] core_data_in;
  wire [511 : 0] core_data_out;
  wire           core_data_out_valid;

  reg [31 : 0]   tmp_data_out;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign core_init    = init_reg;

  assign core_next    = next_reg;

  assign core_keylen  = keylen_reg;

  assign core_rounds  = rounds_reg;

  assign core_key     = {key_reg[0], key_reg[1], key_reg[2], key_reg[3],
                         key_reg[4], key_reg[5], key_reg[6], key_reg[7]};

  assign core_iv      = {iv0_reg, iv1_reg};

  assign core_data_in = {data_in0_reg, data_in1_reg, data_in2_reg, data_in3_reg,
                         data_in4_reg, data_in5_reg, data_in6_reg, data_in7_reg,
                         data_in8_reg, data_in9_reg, data_in10_reg, data_in11_reg,
                         data_in12_reg, data_in13_reg, data_in14_reg, data_in15_reg};

  assign data_out = tmp_data_out;


  //----------------------------------------------------------------
  // core instantiation.
  //----------------------------------------------------------------
  chacha_core core (
                    .clk(clk),
                    .reset_n(reset_n),

                    .init(core_init),
                    .next(core_next),

                    .key(core_key),
                    .keylen(core_keylen),
                    .iv(core_iv),
                    .rounds(core_rounds),

                    .data_in(core_data_in),

                    .ready(core_ready),

                    .data_out(core_data_out),
                    .data_out_valid(core_data_out_valid)
                   );


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
          init_reg           <= 0;
          next_reg           <= 0;
          ready_reg          <= 0;
          keylen_reg         <= 0;
          rounds_reg         <= 5'b00000;
          data_out_valid_reg <= 0;

          key_reg[0]         <= 32'h00000000;
          key_reg[1]         <= 32'h00000000;
          key_reg[2]         <= 32'h00000000;
          key_reg[3]         <= 32'h00000000;
          key_reg[4]         <= 32'h00000000;
          key_reg[5]         <= 32'h00000000;
          key_reg[6]         <= 32'h00000000;
          key_reg[7]         <= 32'h00000000;

          iv0_reg            <= 32'h00000000;
          iv1_reg            <= 32'h00000000;

          data_in0_reg       <= 32'h00000000;
          data_in1_reg       <= 32'h00000000;
          data_in2_reg       <= 32'h00000000;
          data_in3_reg       <= 32'h00000000;
          data_in4_reg       <= 32'h00000000;
          data_in5_reg       <= 32'h00000000;
          data_in6_reg       <= 32'h00000000;
          data_in7_reg       <= 32'h00000000;
          data_in8_reg       <= 32'h00000000;
          data_in9_reg       <= 32'h00000000;
          data_in10_reg      <= 32'h00000000;
          data_in11_reg      <= 32'h00000000;
          data_in12_reg      <= 32'h00000000;
          data_in13_reg      <= 32'h00000000;
          data_in14_reg      <= 32'h00000000;
          data_in15_reg      <= 32'h00000000;

          data_out0_reg      <= 32'h00000000;
          data_out1_reg      <= 32'h00000000;
          data_out2_reg      <= 32'h00000000;
          data_out3_reg      <= 32'h00000000;
          data_out4_reg      <= 32'h00000000;
          data_out5_reg      <= 32'h00000000;
          data_out6_reg      <= 32'h00000000;
          data_out7_reg      <= 32'h00000000;
          data_out8_reg      <= 32'h00000000;
          data_out9_reg      <= 32'h00000000;
          data_out10_reg     <= 32'h00000000;
          data_out11_reg     <= 32'h00000000;
          data_out12_reg     <= 32'h00000000;
          data_out13_reg     <= 32'h00000000;
          data_out14_reg     <= 32'h00000000;
          data_out15_reg     <= 32'h00000000;
        end
      else
        begin
          ready_reg          <= core_ready;
          data_out_valid_reg <= core_data_out_valid;

          if (ctrl_we)
            begin
              init_reg <= data_in[CTRL_INIT_BIT];
              next_reg <= data_in[CTRL_NEXT_BIT];
            end

          if (keylen_we)
            begin
              keylen_reg <= data_in[KEYLEN_BIT];
            end

          if (rounds_we)
            begin
              rounds_reg <= data_in[ROUNDS_HIGH_BIT : ROUNDS_LOW_BIT];
            end

          if (key_we)
            begin
              key_reg[address[2 : 0]] <= data_in;
            end

          if (iv0_we)
            begin
              iv0_reg <= data_in;
            end

          if (iv1_we)
            begin
              iv1_reg <= data_in;
            end

          if (data_in0_we)
            begin
              data_in0_reg <= data_in;
            end

          if (data_in1_we)
            begin
              data_in1_reg <= data_in;
            end

          if (data_in2_we)
            begin
              data_in2_reg <= data_in;
            end

          if (data_in3_we)
            begin
              data_in3_reg <= data_in;
            end

          if (data_in4_we)
            begin
              data_in4_reg <= data_in;
            end

          if (data_in5_we)
            begin
              data_in5_reg <= data_in;
            end

          if (data_in6_we)
            begin
              data_in6_reg <= data_in;
            end

          if (data_in7_we)
            begin
              data_in7_reg <= data_in;
            end

          if (data_in8_we)
            begin
              data_in8_reg <= data_in;
            end

          if (data_in9_we)
            begin
              data_in9_reg <= data_in;
            end

          if (data_in10_we)
            begin
              data_in10_reg <= data_in;
            end

          if (data_in11_we)
            begin
              data_in11_reg <= data_in;
            end

          if (data_in12_we)
            begin
              data_in12_reg <= data_in;
            end

          if (data_in13_we)
            begin
              data_in13_reg <= data_in;
            end

          if (data_in14_we)
            begin
              data_in14_reg <= data_in;
            end

          if (data_in15_we)
            begin
              data_in15_reg <= data_in;
            end

          if (core_data_out_valid)
            begin
              data_out0_reg  <= core_data_out[511 : 480];
              data_out1_reg  <= core_data_out[479 : 448];
              data_out2_reg  <= core_data_out[447 : 416];
              data_out3_reg  <= core_data_out[415 : 384];
              data_out4_reg  <= core_data_out[383 : 352];
              data_out5_reg  <= core_data_out[351 : 320];
              data_out6_reg  <= core_data_out[319 : 288];
              data_out7_reg  <= core_data_out[287 : 256];
              data_out8_reg  <= core_data_out[255 : 224];
              data_out9_reg  <= core_data_out[223 : 192];
              data_out10_reg <= core_data_out[191 : 160];
              data_out11_reg <= core_data_out[159 : 128];
              data_out12_reg <= core_data_out[127 :  96];
              data_out13_reg <= core_data_out[95  :  64];
              data_out14_reg <= core_data_out[63  :  32];
              data_out15_reg <= core_data_out[31  :   0];
            end
        end
    end // reg_update


  //----------------------------------------------------------------
  // Address decoder logic.
  //----------------------------------------------------------------
  always @*
    begin : addr_decoder
      ctrl_we      = 0;
      keylen_we    = 0;
      rounds_we    = 0;

      key_we       = 0;

      iv0_we       = 0;
      iv1_we       = 0;

      data_in0_we  = 0;
      data_in1_we  = 0;
      data_in2_we  = 0;
      data_in3_we  = 0;
      data_in4_we  = 0;
      data_in5_we  = 0;
      data_in6_we  = 0;
      data_in7_we  = 0;
      data_in8_we  = 0;
      data_in9_we  = 0;
      data_in10_we = 0;
      data_in11_we = 0;
      data_in12_we = 0;
      data_in13_we = 0;
      data_in14_we = 0;
      data_in15_we = 0;

      tmp_data_out = 32'h00000000;

      if (cs)
        begin
          if (write_read)
            begin
              if ((address >= ADDR_KEY0) && (address <= ADDR_KEY7))
                key_we  = 1;

              case (address)
                ADDR_CTRL:
                  begin
                    ctrl_we  = 1;
                  end

                ADDR_KEYLEN:
                  begin
                    keylen_we = 1;
                  end

                ADDR_ROUNDS:
                  begin
                    rounds_we  = 1;
                  end

                ADDR_IV0:
                  begin
                    iv0_we = 1;
                  end

                ADDR_IV1:
                  begin
                    iv1_we = 1;
                  end

                ADDR_DATA_IN0:
                  begin
                    data_in0_we = 1;
                  end

                ADDR_DATA_IN1:
                  begin
                    data_in1_we = 1;
                  end

                ADDR_DATA_IN2:
                  begin
                    data_in2_we = 1;
                  end

                ADDR_DATA_IN3:
                  begin
                    data_in3_we = 1;
                  end

                ADDR_DATA_IN4:
                  begin
                    data_in4_we = 1;
                  end

                ADDR_DATA_IN5:
                  begin
                    data_in5_we = 1;
                  end

                ADDR_DATA_IN6:
                  begin
                    data_in6_we = 1;
                  end

                ADDR_DATA_IN7:
                  begin
                    data_in7_we = 1;
                  end

                ADDR_DATA_IN8:
                  begin
                    data_in8_we = 1;
                  end

                ADDR_DATA_IN9:
                  begin
                    data_in9_we = 1;
                  end

                ADDR_DATA_IN10:
                  begin
                    data_in10_we = 1;
                  end

                ADDR_DATA_IN11:
                  begin
                    data_in11_we = 1;
                  end

                ADDR_DATA_IN12:
                  begin
                    data_in12_we = 1;
                  end

                ADDR_DATA_IN13:
                  begin
                    data_in13_we = 1;
                  end

                ADDR_DATA_IN14:
                  begin
                    data_in14_we = 1;
                  end

                ADDR_DATA_IN15:
                  begin
                    data_in15_we = 1;
                  end

                default:
                  begin
                    // Empty since default assignemnts are handled
                    // outside of the if-mux construct.
                  end
              endcase // case (address)
            end // if (write_read)

          else
            begin
              if ((address >= ADDR_KEY0) && (address <= ADDR_KEY7))
                tmp_data_out = key_reg[address[2 : 0]];

              case (address)
                ADDR_CTRL:
                  begin
                    tmp_data_out = {30'h0, next_reg, init_reg};
                  end

                ADDR_STATUS:
                  begin
                    tmp_data_out = {30'h0, data_out_valid_reg, ready_reg};
                  end

                ADDR_KEYLEN:
                  begin
                    tmp_data_out = {31'h0, keylen_reg};
                  end

                ADDR_ROUNDS:
                  begin
                    tmp_data_out = {27'h0, rounds_reg};
                  end

                ADDR_IV0:
                  begin
                    tmp_data_out = iv0_reg;
                  end

                ADDR_IV1:
                  begin
                    tmp_data_out = iv1_reg;
                  end

                ADDR_DATA_OUT0:
                  begin
                    tmp_data_out = data_out0_reg;
                  end

                ADDR_DATA_OUT1:
                  begin
                    tmp_data_out = data_out1_reg;
                  end

                ADDR_DATA_OUT2:
                  begin
                    tmp_data_out = data_out2_reg;
                  end

                ADDR_DATA_OUT3:
                  begin
                    tmp_data_out = data_out3_reg;
                  end

                ADDR_DATA_OUT4:
                  begin
                    tmp_data_out = data_out4_reg;
                  end

                ADDR_DATA_OUT5:
                  begin
                    tmp_data_out = data_out5_reg;
                  end

                ADDR_DATA_OUT6:
                  begin
                    tmp_data_out = data_out6_reg;
                  end

                ADDR_DATA_OUT7:
                  begin
                    tmp_data_out = data_out7_reg;
                  end

                ADDR_DATA_OUT8:
                  begin
                    tmp_data_out = data_out8_reg;
                  end

                ADDR_DATA_OUT9:
                  begin
                    tmp_data_out = data_out9_reg;
                  end

                ADDR_DATA_OUT10:
                  begin
                    tmp_data_out = data_out10_reg;
                  end

                ADDR_DATA_OUT11:
                  begin
                    tmp_data_out = data_out11_reg;
                  end

                ADDR_DATA_OUT12:
                  begin
                    tmp_data_out = data_out12_reg;
                  end

                ADDR_DATA_OUT13:
                  begin
                    tmp_data_out = data_out13_reg;
                  end

                ADDR_DATA_OUT14:
                  begin
                    tmp_data_out = data_out14_reg;
                  end

                ADDR_DATA_OUT15:
                  begin
                    tmp_data_out = data_out15_reg;
                  end

                default:
                  begin
                  end
              endcase // case (address)
            end
        end
    end // addr_decoder
endmodule // chacha

//======================================================================
// EOF chacha.v
//======================================================================
