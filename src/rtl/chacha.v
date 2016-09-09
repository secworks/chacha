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
  localparam ADDR_NAME0       = 8'h00;
  localparam ADDR_NAME1       = 8'h01;
  localparam ADDR_VERSION     = 8'h02;

  localparam ADDR_CTRL        = 8'h08;
  localparam CTRL_INIT_BIT    = 0;
  localparam CTRL_NEXT_BIT    = 1;

  localparam ADDR_STATUS      = 8'h09;
  localparam STATUS_READY_BIT = 0;

  localparam ADDR_KEYLEN      = 8'h0a;
  localparam KEYLEN_BIT       = 0;
  localparam ADDR_ROUNDS      = 8'h0b;
  localparam ROUNDS_HIGH_BIT  = 4;
  localparam ROUNDS_LOW_BIT   = 0;

  localparam ADDR_KEY0        = 8'h10;
  localparam ADDR_KEY7        = 8'h17;

  localparam ADDR_IV0         = 8'h20;
  localparam ADDR_IV1         = 8'h21;

  localparam ADDR_DATA_IN0    = 8'h40;
  localparam ADDR_DATA_IN15   = 8'h4f;

  localparam ADDR_DATA_OUT0   = 8'h80;
  localparam ADDR_DATA_OUT15  = 8'h8f;

  localparam CORE_NAME0          = 32'h63686163; // "chac"
  localparam CORE_NAME1          = 32'h68612020; // "ha  "
  localparam CORE_VERSION        = 32'h302e3830; // "0.80"


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

  reg [31 : 0] data_in_reg [0 : 15];
  reg          data_in_we;

  reg [511 : 0] data_out_reg;


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

  assign core_data_in = {data_in_reg[00], data_in_reg[01], data_in_reg[02], data_in_reg[03],
                         data_in_reg[04], data_in_reg[05], data_in_reg[06], data_in_reg[07],
                         data_in_reg[08], data_in_reg[09], data_in_reg[10], data_in_reg[11],
                         data_in_reg[12], data_in_reg[13], data_in_reg[14], data_in_reg[15]};

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
    begin : reg_update
     integer i;

      if (!reset_n)
        begin
          init_reg           <= 0;
          next_reg           <= 0;
          ready_reg          <= 0;
          keylen_reg         <= 0;
          rounds_reg         <= 5'h0;
          data_out_valid_reg <= 0;
          iv0_reg            <= 32'h0;
          iv1_reg            <= 32'h0;
          data_out_reg       <= 512'h0;

          for (i = 0 ; i < 8 ; i = i + 1)
            key_reg[i] <= 32'h0;

          for (i = 0 ; i < 16 ; i = i + 1)
            data_in_reg[i] <= 32'h0;
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
            keylen_reg <= data_in[KEYLEN_BIT];

          if (rounds_we)
            rounds_reg <= data_in[ROUNDS_HIGH_BIT : ROUNDS_LOW_BIT];

          if (key_we)
            key_reg[address[2 : 0]] <= data_in;

          if (iv0_we)
            iv0_reg <= data_in;

          if (iv1_we)
            iv1_reg <= data_in;

          if (data_in_we)
            data_in_reg[address[3 : 0]] <= data_in;

          if (core_data_out_valid)
            data_out_reg <= core_data_out;
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
      data_in_we   = 0;
      tmp_data_out = 32'h0;

      if (cs)
        begin
          if (write_read)
            begin
              if ((address >= ADDR_KEY0) && (address <= ADDR_KEY7))
                key_we = 1;

              if ((address >= ADDR_DATA_IN0) && (address <= ADDR_DATA_IN15))
                data_in_we = 1;

              case (address)
                ADDR_CTRL: ctrl_we = 1;
                ADDR_KEYLEN: keylen_we = 1;
                ADDR_ROUNDS: rounds_we = 1;
                ADDR_IV0:    iv0_we = 1;
                ADDR_IV1:    iv1_we = 1;

                default:
                  begin
                  end
              endcase // case (address)
            end // if (write_read)

          else
            begin
              if ((address >= ADDR_KEY0) && (address <= ADDR_KEY7))
                tmp_data_out = key_reg[address[2 : 0]];

              if ((address >= ADDR_DATA_OUT0) && (address <= ADDR_DATA_OUT15))
                tmp_data_out = data_out_reg[(15 - (address - ADDR_DATA_OUT0)) * 32 +: 32];

              case (address)
                ADDR_NAME0:   tmp_data_out = CORE_NAME0;
                ADDR_NAME1:   tmp_data_out = CORE_NAME1;
                ADDR_VERSION: tmp_data_out = CORE_VERSION;
                ADDR_CTRL:    tmp_data_out = {30'h0, next_reg, init_reg};
                ADDR_STATUS:  tmp_data_out = {30'h0, data_out_valid_reg, ready_reg};
                ADDR_KEYLEN:  tmp_data_out = {31'h0, keylen_reg};
                ADDR_ROUNDS:  tmp_data_out = {27'h0, rounds_reg};
                ADDR_IV0:     tmp_data_out = iv0_reg;
                ADDR_IV1:     tmp_data_out = iv1_reg;

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
