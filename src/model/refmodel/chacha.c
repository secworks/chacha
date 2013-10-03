//======================================================================
//
// chacha.c
//
// Testvector generator.
// Heavily based on chacha ref model by DJB.
//
//
//======================================================================

//------------------------------------------------------------------
// Includes.
//------------------------------------------------------------------
#include <stdio.h>
#include <stdint.h>


//------------------------------------------------------------------
// Types
//------------------------------------------------------------------
typedef struct
{
  uint32_t input[16];
} chacha_ctx;


//------------------------------------------------------------------
// Macros.
//------------------------------------------------------------------
#define ROTATE(v,c) ((((v) << (c)) & 0xffffffff) | ((v) >> (32 - (c))))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (((v) + (w)) & 0xffffffff)
#define PLUSONE(v) (PLUS((v),1))

// Little endian machine assumed (x86-64)
#define U32TO32_LITTLE(v) (v)
#define U32TO8_LITTLE(p, v) (((uint32_t*)(p))[0] = U32TO32_LITTLE(v))
#define U8TO32_LITTLE(p) U32TO32_LITTLE(((uint32_t*)(p))[0])

#define QUARTERROUND(a,b,c,d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);


//------------------------------------------------------------------
// Constants.
//------------------------------------------------------------------
static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";


//------------------------------------------------------------------
// salsa20_wordtobyte
// 
// This is basically the doubleround function.
// Note: Is _not_ salsa20, but chacha. And does much more than
// simply convert from words to bytes.
//------------------------------------------------------------------
static void salsa20_wordtobyte(uint8_t output[64],const uint32_t input[16])
{
  uint32_t x[16];
  int32_t i;

  for (i = 0;i < 16;++i) { 
    x[i] = input[i];
  }

  for (i = 8 ; i > 0 ; i -= 2) {
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
    x[i] = PLUS(x[i],input[i]);
  }

  for (i = 0;i < 16;++i) {
    U32TO8_LITTLE(output + 4 * i,x[i]);
  }
}


//------------------------------------------------------------------
// keysetup
//
// Note: ivbits is not used.
//------------------------------------------------------------------
void keysetup(chacha_ctx *x,const uint8_t *k,uint32_t kbits,uint32_t ivbits)
{
  const char *constants;

  x->input[4] = U8TO32_LITTLE(k + 0);
  x->input[5] = U8TO32_LITTLE(k + 4);
  x->input[6] = U8TO32_LITTLE(k + 8);
  x->input[7] = U8TO32_LITTLE(k + 12);
  if (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } else { /* kbits == 128 */
    constants = tau;
  }
  x->input[8] = U8TO32_LITTLE(k + 0);
  x->input[9] = U8TO32_LITTLE(k + 4);
  x->input[10] = U8TO32_LITTLE(k + 8);
  x->input[11] = U8TO32_LITTLE(k + 12);
  x->input[0] = U8TO32_LITTLE(constants + 0);
  x->input[1] = U8TO32_LITTLE(constants + 4);
  x->input[2] = U8TO32_LITTLE(constants + 8);
  x->input[3] = U8TO32_LITTLE(constants + 12);
}


//------------------------------------------------------------------
// ivsetup()
//
// Set iv in the context. This also resets the block counter.
//------------------------------------------------------------------
void ivsetup(chacha_ctx *x,const uint8_t *iv)
{
  x->input[12] = 0;
  x->input[13] = 0;
  x->input[14] = U8TO32_LITTLE(iv + 0);
  x->input[15] = U8TO32_LITTLE(iv + 4);
}


//------------------------------------------------------------------
// encrypt_bytes()
// 
// Given a pointer to message m of cleartext bytes will use the
// current context to encrypt bytes number of bytes of m.
// The ciphertext will be bytes in c.
//------------------------------------------------------------------
void encrypt_bytes(chacha_ctx *x,const uint8_t *m,uint8_t *c,uint32_t bytes)
{
  uint8_t output[64];
  int i;

  if (!bytes) return;
  for (;;) {
    salsa20_wordtobyte(output,x->input);
    x->input[12] = PLUSONE(x->input[12]);
    if (!x->input[12]) {
      x->input[13] = PLUSONE(x->input[13]);
      /* stopping at 2^70 bytes per nonce is user's responsibility */
    }
    if (bytes <= 64) {
      for (i = 0;i < bytes;++i) c[i] = m[i] ^ output[i];
      return;
    }
    for (i = 0;i < 64;++i) c[i] = m[i] ^ output[i];
    bytes -= 64;
    c += 64;
    m += 64;
  }
}


//------------------------------------------------------------------
//------------------------------------------------------------------
void decrypt_bytes(chacha_ctx *x,const uint8_t *c,uint8_t *m,uint32_t bytes)
{
  encrypt_bytes(x,c,m,bytes);
}


//------------------------------------------------------------------
//------------------------------------------------------------------
void keystream_bytes(chacha_ctx *x,uint8_t *stream,uint32_t bytes)
{
  uint32_t i;
  for (i = 0;i < bytes;++i) stream[i] = 0;
  encrypt_bytes(x,stream,stream,bytes);
}


//------------------------------------------------------------------
// dump_ctx()
//
// Given a 
//------------------------------------------------------------------
dump_ctx(chacha_ctr *x)
{

}


//------------------------------------------------------------------
// main()
//
// Set up context and generate test vectors for different
// combinations of key, iv, blocks etc.
//------------------------------------------------------------------
int main(void)
{
  printf("bajs!\n");
  
  chacha_ctx my_ctx;

  uint32_t my_keybits = 128;
  uint8_t my_key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  uint32_t my_ivbits = 64;
  uint8_t my_iv[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  keysetup(&my_ctx, my_key, my_keybits, my_ivbits);
  ivsetup(&my_ctx, my_iv);

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

  encrypt_bytes(&my_ctx, testdata1, my_result, 64);
  return 0;
}

