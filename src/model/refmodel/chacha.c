//======================================================================
//
// chacha.c
// --------
//
// ChaCha reference model and test vector generator. Very much
// needed for ChaCha. The code is heavily based on the chacha ref 
// model by DJB. This code is self contained, contains test vectors
// and is cleaned up somewhat. (Does not reference Salsa20 functions
// etc.)
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

//------------------------------------------------------------------
// Includes.
//------------------------------------------------------------------
#include <stdio.h>
#include <stdint.h>


//------------------------------------------------------------------
// Types.
//------------------------------------------------------------------
// The chacha state context.
typedef struct
{
  uint32_t state[16];
  uint8_t rounds; 
} chacha_ctx;


//------------------------------------------------------------------
// Macros.
//------------------------------------------------------------------
// Basic 32-bit operators.
#define ROTATE(v,c) ((uint32_t)((v) << (c)) | ((v) >> (32 - (c))))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) ((uint32_t)((v) + (w)))
#define PLUSONE(v) (PLUS((v), 1))

// Little endian machine assumed (x86-64).
#define U32TO32_LITTLE(v) (v)
#define U32TO8_LITTLE(p, v) (((uint32_t*)(p))[0] = U32TO32_LITTLE(v))
#define U8TO32_LITTLE(p) U32TO32_LITTLE(((uint32_t*)(p))[0])

#define QUARTERROUND(a, b, c, d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);


//------------------------------------------------------------------
// Constants.
//------------------------------------------------------------------
static const char SIGMA[16] = "expand 32-byte k";
static const char TAU[16] = "expand 16-byte k";


//------------------------------------------------------------------
// doublerounds()
// 
// Perform rounds number of rounds.
// TODO: Change output format to 16 words.
//------------------------------------------------------------------
static void doublerounds(uint8_t output[64], const uint32_t input[16], uint8_t rounds)
{
  uint32_t x[16];
  int32_t i;

  for (i = 0;i < 16;++i) { 
    x[i] = input[i];
  }

  for (i = rounds ; i > 0 ; i -= 2) {
    QUARTERROUND( 0, 4, 8,12)
    QUARTERROUND( 1, 5, 9,13)
    QUARTERROUND( 2, 6,10,14)
    QUARTERROUND( 3, 7,11,15)
    QUARTERROUND( 0, 5,10,15)
    QUARTERROUND( 1, 6,11,12)
    QUARTERROUND( 2, 7, 8,13)
    QUARTERROUND( 3, 4, 9,14)
  }

  for (i = 0;i < 16;++i) {
    x[i] = PLUS(x[i], input[i]);
  }

  for (i = 0;i < 16;++i) {
    U32TO8_LITTLE(output + 4 * i, x[i]);
  }
}


//------------------------------------------------------------------
// keysetup()
//
// Initializes the given context with key and constants.
// Note: ivbits is not used.
//
// TODO: Change to a function that also accepts iv.
//------------------------------------------------------------------
void keysetup(chacha_ctx *x, const uint8_t *k, uint32_t kbits)
{
  const char *constants;

  x->state[4] = U8TO32_LITTLE(k + 0);
  x->state[5] = U8TO32_LITTLE(k + 4);
  x->state[6] = U8TO32_LITTLE(k + 8);
  x->state[7] = U8TO32_LITTLE(k + 12);

  if (kbits == 256) { /* recommended */
    k += 16;
    constants = SIGMA;
  } else { /* kbits == 128 */
    constants = TAU;
  }

  x->state[8]  = U8TO32_LITTLE(k + 0);
  x->state[9]  = U8TO32_LITTLE(k + 4);
  x->state[10] = U8TO32_LITTLE(k + 8);
  x->state[11] = U8TO32_LITTLE(k + 12);
  x->state[0]  = U8TO32_LITTLE(constants + 0);
  x->state[1]  = U8TO32_LITTLE(constants + 4);
  x->state[2]  = U8TO32_LITTLE(constants + 8);
  x->state[3]  = U8TO32_LITTLE(constants + 12);
}


//------------------------------------------------------------------
// ivsetup()
//
// Set iv in the context. This also resets the block counter.
//------------------------------------------------------------------
void ivsetup(chacha_ctx *x, const uint8_t *iv)
{
  x->state[12] = 0;
  x->state[13] = 0;
  x->state[14] = U8TO32_LITTLE(iv + 0);
  x->state[15] = U8TO32_LITTLE(iv + 4);
}


//------------------------------------------------------------------
// next()
// 
// Given a pointer to the next block m of 64 cleartext bytes will 
// use the given context to transform (encrypt/decrypt) the 
// block. The result will be stored in c.
//------------------------------------------------------------------
void next(chacha_ctx *ctx, const uint8_t *m, uint8_t *c)
{
  // Temporary internal state x.
  uint8_t x[64];
  uint8_t i;

  
  // Update the internal state and increase the block counter.
  doublerounds(x, ctx->state, ctx->rounds);
  ctx->state[12] = PLUSONE(ctx->state[12]);
  if (!ctx->state[12]) {
    ctx->state[13] = PLUSONE(ctx->state[13]);
  }

  // XOR the input block with the new temporal state to
  // create the transformed block.
  for (i = 0 ; i < 64 ; ++i) { 
    c[i] = m[i] ^ x[i];
  }
}


//------------------------------------------------------------------
// dump_ctx()
//
// Given a chacha context will dump the contents to std out.
//------------------------------------------------------------------
void dump_ctx(chacha_ctx *ctx)
{
  uint8_t i;

  printf("Current ChaCha context:\n");
  printf("-----------------------\n");
  
  for (i = 0; i < 16; i++) {
    printf("ctx[%02d] = 0x%08x\n", i, ctx->state[i]);
  }
  printf("\n");
}


//------------------------------------------------------------------
// dump_block()
//
// Given a block of 64 bytes, dump the contents to std out.
//------------------------------------------------------------------
void dump_block(uint8_t block[64])
{
  uint8_t i;

  for (i = 0 ; i < 64 ; i++) {
    if ((i % 8) == 0) {
        printf("block[%02d - %02d]: ", i, (i + 7));
      }

    printf("0x%02x ", block[i]);

    if (((i + 1) % 8) == 0) {
      printf("\n");
    }
  }
  printf("\n");
}


//------------------------------------------------------------------
// init_ctx()
//
// Init a given ChaCha context by setting state to zero and
// setting the given number of rounds.
//------------------------------------------------------------------
void init_ctx(chacha_ctx *ctx, uint8_t rounds)
{
  uint8_t i;

  for (i = 0 ; i < 16 ; i++) {
    ctx->state[i] = 0;
  }

  ctx->rounds = rounds;
}


//------------------------------------------------------------------
// main()
//
// Set up context and generate test vectors for different
// combinations of key, iv, blocks etc.
//------------------------------------------------------------------
int main(void)
{
  printf("Generating test vectors for ChaCha with 8 rounds.");

  // Create a context.
  chacha_ctx my_ctx;

  // Starting with 8 rouns.
  init_ctx(&my_ctx, 8);

  uint32_t my_keybits = 256;
  uint8_t my_key[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  uint8_t my_iv[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  keysetup(&my_ctx, my_key, my_keybits);
  dump_ctx(&my_ctx);
  ivsetup(&my_ctx, my_iv);
  dump_ctx(&my_ctx);

  uint8_t testdata1[64] =  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  uint8_t my_result[64] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  next(&my_ctx, testdata1, my_result);
  dump_ctx(&my_ctx);
  dump_block(my_result);

  return 0;
}


//======================================================================
// EOF chacha.c
//======================================================================
