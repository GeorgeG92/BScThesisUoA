static const char _NR[] = {
  0x4e,0x61,0x62,0x69,0x6c,0x20,0x53,0x2e,0x20,
  0x41,0x6c,0x20,0x52,0x61,0x6d,0x6c,0x69,0x00 };

#include <stdlib.h>
#include <stddef.h>
#include <time.h> 
#include <sys/timeb.h>
#include <string.h>

#ifdef WIN32
#include <process.h>
#endif

#include "../inc/oaes_config.h"
#include "../inc/oaes_lib.h"

#ifdef OAES_HAVE_ISAAC
#include "isaac/rand.h"
#include "isaac/standard.h"


#ifdef OAES_DEBUG
char msg2[] = "My macro is defined in lib";
#else
char msg2[] = "My macro is NOT defined in lib";
#endif


#define OAES_RAND(x) rand(x)
#else
#define OAES_RAND(x) rand()
#endif // OAES_HAVE_ISAAC


#define OAES_RKEY_LEN 4
#define OAES_COL_LEN 4
#define OAES_ROUND_BASE 7

// the block is padded
#define OAES_FLAG_PAD 0x01

#ifndef min
# define min(a,b) (((a)<(b)) ? (a) : (b))
#endif /* min */


#include "../cuda/b.h"



typedef struct _oaes_key
{
  size_t data_len;
  uint8_t *data;
  size_t exp_data_len;
  uint8_t *exp_data;
  size_t num_keys;
  size_t key_base;
} oaes_key;

typedef struct _oaes_ctx
{
#ifdef OAES_HAVE_ISAAC
  randctx * rctx;
#endif // OAES_HAVE_ISAAC

#ifdef OAES_DEBUG
  oaes_step_cb step_cb;
#endif // OAES_DEBUG

  oaes_key * key;
  OAES_OPTION options;
  uint8_t iv[OAES_BLOCK_SIZE];
} oaes_ctx;


#ifdef OAES_HAVE_ISAAC
randctx * r_rctx;
#endif


#ifdef OAES_DEBUG
oaes_step_cb r_step_cb;
#endif

extern int func(size_t *c_len, uint8_t *c, size_t *m_len, OAES_RET *_rc, oaes_ctx **_ctx);
extern int func2(uint8_t *c, size_t *m_len, OAES_RET *_rc, oaes_ctx **ctx, uint8_t *pad, OAES_RET *pad_check);

// "OAES<8-bit header version><8-bit type><16-bit options><8-bit flags><56-bit reserved>"
static uint8_t oaes_header[OAES_BLOCK_SIZE] = {
  //     0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    a,    b,    c,    d,    e,    f,
  /*0*/  0x4f, 0x41, 0x45, 0x53, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static uint8_t oaes_gf_8[] = {
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

static uint8_t oaes_sub_byte_value[16][16] = {
  //     0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    a,    b,    c,    d,    e,    f,
  /*0*/  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  /*1*/  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  /*2*/  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  /*3*/  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  /*4*/  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  /*5*/  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  /*6*/  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  /*7*/  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  /*8*/  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  /*9*/  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  /*a*/  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  /*b*/  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  /*c*/  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  /*d*/  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  /*e*/  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  /*f*/  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static OAES_RET oaes_sub_byte( uint8_t * byte )
{
  size_t _x, _y;
  
  if( NULL == byte )
    return OAES_RET_ARG1;

  _x = _y = *byte;
  _x &= 0x0f;
  _y &= 0xf0;
  _y >>= 4;
  *byte = oaes_sub_byte_value[_y][_x];
  
  return OAES_RET_SUCCESS;
}

static OAES_RET oaes_word_rot_right( uint8_t word[OAES_COL_LEN] )
{
  uint8_t _temp[OAES_COL_LEN];
  
  if( NULL == word )
    return OAES_RET_ARG1;

  memcpy( _temp + 1, word, OAES_COL_LEN - 1 );
  _temp[0] = word[OAES_COL_LEN - 1];
  memcpy( word, _temp, OAES_COL_LEN );
  
  return OAES_RET_SUCCESS;
}

static OAES_RET oaes_word_rot_left( uint8_t word[OAES_COL_LEN] )
{
  uint8_t _temp[OAES_COL_LEN];
  
  if( NULL == word )
    return OAES_RET_ARG1;

  memcpy( _temp, word + 1, OAES_COL_LEN - 1 );
  _temp[OAES_COL_LEN - 1] = word[0];
  memcpy( word, _temp, OAES_COL_LEN );
  
  return OAES_RET_SUCCESS;
}

OAES_RET oaes_sprintf(
    char * buf, size_t * buf_len, const uint8_t * data, size_t data_len )
{
  size_t _i, _buf_len_in;
  char _temp[4];
  
  if( NULL == buf_len )
    return OAES_RET_ARG2;

  _buf_len_in = *buf_len;
  *buf_len = data_len * 3 + data_len / OAES_BLOCK_SIZE + 1;
  
  if( NULL == buf )
    return OAES_RET_SUCCESS;

  if( *buf_len > _buf_len_in )
    return OAES_RET_BUF;

  if( NULL == data )
    return OAES_RET_ARG3;

  strcpy( buf, "" );
  for( _i = 0; _i < data_len; _i++ )
  {
    sprintf( _temp, "%02x ", data[_i] );
    strcat( buf, _temp );
    if( _i && 0 == ( _i + 1 ) % OAES_BLOCK_SIZE )
      strcat( buf, "\n" );
  }
  return OAES_RET_SUCCESS;
}

#ifdef OAES_HAVE_ISAAC
static void oaes_get_seed( char buf[RANDSIZ + 1] )
{
  struct timeb timer;
  struct tm *gmTimer;
  char * _test = NULL;
  
  ftime (&timer);
  gmTimer = gmtime( &timer.time );
  _test = (char *) calloc( sizeof( char ), timer.millitm );
  sprintf( buf, "%04d%02d%02d%02d%02d%02d%03d%p%d",
    gmTimer->tm_year + 1900, gmTimer->tm_mon + 1, gmTimer->tm_mday,
    gmTimer->tm_hour, gmTimer->tm_min, gmTimer->tm_sec, timer.millitm,
    _test + timer.millitm, getpid() );
  
  if( _test )
    free( _test );
}
#else
static uint32_t oaes_get_seed()
{
  struct timeb timer;
  struct tm *gmTimer;
  char * _test = NULL;
  uint32_t _ret = 0;
  
  ftime (&timer);
  gmTimer = gmtime( &timer.time );
  _test = (char *) calloc( sizeof( char ), timer.millitm );
  _ret = gmTimer->tm_year + 1900 + gmTimer->tm_mon + 1 + gmTimer->tm_mday +
      gmTimer->tm_hour + gmTimer->tm_min + gmTimer->tm_sec + timer.millitm +
      (uint32_t) ( _test + timer.millitm ) + getpid();

  if( _test )
    free( _test );
  
  return _ret;
}
#endif // OAES_HAVE_ISAAC

static OAES_RET oaes_key_destroy( oaes_key ** key )
{
  if( NULL == *key )
    return OAES_RET_SUCCESS;
  
  if( (*key)->data )
  {
    free( (*key)->data );
    (*key)->data = NULL;
  }
  
  if( (*key)->exp_data )
  {
    free( (*key)->exp_data );
    (*key)->exp_data = NULL;
  }
  
  (*key)->data_len = 0;
  (*key)->exp_data_len = 0;
  (*key)->num_keys = 0;
  (*key)->key_base = 0;
  free( *key );
  *key = NULL;
  
  return OAES_RET_SUCCESS;
}

static OAES_RET oaes_key_expand( OAES_CTX * ctx )
{
  size_t _i, _j;
  oaes_ctx * _ctx = (oaes_ctx *) ctx;
  
  if( NULL == _ctx )
    return OAES_RET_ARG1;
  
  if( NULL == _ctx->key )
    return OAES_RET_NOKEY;
  
  _ctx->key->key_base = _ctx->key->data_len / OAES_RKEY_LEN;
  _ctx->key->num_keys =  _ctx->key->key_base + OAES_ROUND_BASE;
          
  _ctx->key->exp_data_len = _ctx->key->num_keys * OAES_RKEY_LEN * OAES_COL_LEN;
  _ctx->key->exp_data = (uint8_t *)
      calloc( _ctx->key->exp_data_len, sizeof( uint8_t ));
  
  if( NULL == _ctx->key->exp_data )
    return OAES_RET_MEM;
  
  // the first _ctx->key->data_len are a direct copy
  memcpy( _ctx->key->exp_data, _ctx->key->data, _ctx->key->data_len );

  // apply ExpandKey algorithm for remainder
  for( _i = _ctx->key->key_base; _i < _ctx->key->num_keys * OAES_RKEY_LEN; _i++ )
  {
    uint8_t _temp[OAES_COL_LEN];
    
    memcpy( _temp,
        _ctx->key->exp_data + ( _i - 1 ) * OAES_RKEY_LEN, OAES_COL_LEN );
    
    // transform key column
    if( 0 == _i % _ctx->key->key_base )
    {
      oaes_word_rot_left( _temp );

      for( _j = 0; _j < OAES_COL_LEN; _j++ )
        oaes_sub_byte( _temp + _j );

      _temp[0] = _temp[0] ^ oaes_gf_8[ _i / _ctx->key->key_base - 1 ];
    }
    else if( _ctx->key->key_base > 6 && 4 == _i % _ctx->key->key_base )
    {
      for( _j = 0; _j < OAES_COL_LEN; _j++ )
        oaes_sub_byte( _temp + _j );
    }
    
    for( _j = 0; _j < OAES_COL_LEN; _j++ )
    {
      _ctx->key->exp_data[ _i * OAES_RKEY_LEN + _j ] =
          _ctx->key->exp_data[ ( _i - _ctx->key->key_base ) *
          OAES_RKEY_LEN + _j ] ^ _temp[_j];
    }
  }
  return OAES_RET_SUCCESS;
}

static OAES_RET oaes_key_gen( OAES_CTX * ctx, size_t key_size )
{
  size_t _i;
  oaes_key * _key = NULL;
  oaes_ctx * _ctx = (oaes_ctx *) ctx;
  OAES_RET _rc = OAES_RET_SUCCESS;
  
  if( NULL == _ctx )
    return OAES_RET_ARG1;
  
  _key = (oaes_key *) calloc( sizeof( oaes_key ), 1 );
  
  if( NULL == _key )
    return OAES_RET_MEM;
  
  if( _ctx->key )
    oaes_key_destroy( &(_ctx->key) );
  
  _key->data_len = key_size;
  _key->data = (uint8_t *) calloc( key_size, sizeof( uint8_t ));
  
  if( NULL == _key->data )
    return OAES_RET_MEM;
  
  memset(_key->data, '0', _key->data_len*sizeof(uint8_t));
  for( _i = 0; _i < key_size; _i++ )
  {
	 uint8_t tempc = (uint8_t) OAES_RAND(_ctx->rctx);
    _key->data[_i] = tempc;
  }
  
  _ctx->key = _key;
  _rc = _rc || oaes_key_expand( ctx );
  
  if( _rc != OAES_RET_SUCCESS )
  {
    oaes_key_destroy( &(_ctx->key) );
    return _rc;
  }
  
  return OAES_RET_SUCCESS;
}

OAES_RET oaes_key_gen_128( OAES_CTX * ctx )
{
  return oaes_key_gen( ctx, 16 );
}

OAES_RET oaes_key_gen_192( OAES_CTX * ctx )
{
  return oaes_key_gen( ctx, 24 );
}

OAES_RET oaes_key_gen_256( OAES_CTX * ctx )
{
  return oaes_key_gen( ctx, 32 );
}

OAES_RET oaes_key_export( OAES_CTX * ctx,
    uint8_t * data, size_t * data_len )
{
  size_t _data_len_in;
  oaes_ctx * _ctx = (oaes_ctx *) ctx;
  
  if( NULL == _ctx )
    return OAES_RET_ARG1;
  
  if( NULL == _ctx->key )
    return OAES_RET_NOKEY;
  
  if( NULL == data_len )
    return OAES_RET_ARG3;

  _data_len_in = *data_len;
  // data + header
  *data_len = _ctx->key->data_len + OAES_BLOCK_SIZE;

  if( NULL == data )
    return OAES_RET_SUCCESS;
  
  if( _data_len_in < *data_len )
    return OAES_RET_BUF;
  
  // header
  memcpy( data, oaes_header, OAES_BLOCK_SIZE );
  data[5] = 0x01;
  data[7] = _ctx->key->data_len;
  memcpy( data + OAES_BLOCK_SIZE, _ctx->key->data, _ctx->key->data_len );
  
  return OAES_RET_SUCCESS;
}

OAES_RET oaes_key_export_data( OAES_CTX * ctx,
    uint8_t * data, size_t * data_len )
{
  size_t _data_len_in;
  oaes_ctx * _ctx = (oaes_ctx *) ctx;
  
  if( NULL == _ctx )
    return OAES_RET_ARG1;
  
  if( NULL == _ctx->key )
    return OAES_RET_NOKEY;
  
  if( NULL == data_len )
    return OAES_RET_ARG3;

  _data_len_in = *data_len;
  *data_len = _ctx->key->data_len;

  if( NULL == data )
    return OAES_RET_SUCCESS;
  
  if( _data_len_in < *data_len )
    return OAES_RET_BUF;
  
  memcpy( data, _ctx->key->data, *data_len );
  
  return OAES_RET_SUCCESS;
}

OAES_RET oaes_key_import( OAES_CTX * ctx,
    const uint8_t * data, size_t data_len )
{
  oaes_ctx * _ctx = (oaes_ctx *) ctx;
  OAES_RET _rc = OAES_RET_SUCCESS;
  int _key_length;
  
  if( NULL == _ctx )
    return OAES_RET_ARG1;
  
  if( NULL == data )
    return OAES_RET_ARG2;
  
  switch( data_len )
  {
    case 16 + OAES_BLOCK_SIZE:
    case 24 + OAES_BLOCK_SIZE:
    case 32 + OAES_BLOCK_SIZE:
      break;
    default:
      return OAES_RET_ARG3;
  }
  
  // header
  if( 0 != memcmp( data, oaes_header, 4 ) )
    return OAES_RET_HEADER;

  // header version
  switch( data[4] )
  {
    case 0x01:
      break;
    default:
      return OAES_RET_HEADER;
  }
  
  // header type
  switch( data[5] )
  {
    case 0x01:
      break;
    default:
      return OAES_RET_HEADER;
  }
  
  // options
  _key_length = data[7];
  switch( _key_length )
  {
    case 16:
    case 24:
    case 32:
      break;
    default:
      return OAES_RET_HEADER;
  }
  
  if( data_len != _key_length + OAES_BLOCK_SIZE )
      return OAES_RET_ARG3;
  
  if( _ctx->key )
    oaes_key_destroy( &(_ctx->key) );
  
  _ctx->key = (oaes_key *) calloc( sizeof( oaes_key ), 1 );
  
  if( NULL == _ctx->key )
    return OAES_RET_MEM;
  
  _ctx->key->data_len = _key_length;
  _ctx->key->data = (uint8_t *)
      calloc( _key_length, sizeof( uint8_t ));
  
  if( NULL == _ctx->key->data )
  {
    oaes_key_destroy( &(_ctx->key) );
    return OAES_RET_MEM;
  }

  memcpy( _ctx->key->data, data + OAES_BLOCK_SIZE, _key_length );
  _rc = _rc || oaes_key_expand( ctx );
  
  if( _rc != OAES_RET_SUCCESS )
  {
    oaes_key_destroy( &(_ctx->key) );
    return _rc;
  }
  
  return OAES_RET_SUCCESS;
}

OAES_RET oaes_key_import_data( OAES_CTX * ctx,
    const uint8_t * data, size_t data_len )
{
  oaes_ctx * _ctx = (oaes_ctx *) ctx;
  OAES_RET _rc = OAES_RET_SUCCESS;
  
  if( NULL == _ctx )
    return OAES_RET_ARG1;
  
  if( NULL == data )
    return OAES_RET_ARG2;
  
  switch( data_len )
  {
    case 16:
    case 24:
    case 32:
      break;
    default:
      return OAES_RET_ARG3;
  }
  
  if( _ctx->key )
    oaes_key_destroy( &(_ctx->key) );
  
  _ctx->key = (oaes_key *) calloc( sizeof( oaes_key ), 1 );
  
  if( NULL == _ctx->key )
    return OAES_RET_MEM;
  
  _ctx->key->data_len = data_len;
  _ctx->key->data = (uint8_t *)
      calloc( data_len, sizeof( uint8_t ));
  
  if( NULL == _ctx->key->data )
  {
    oaes_key_destroy( &(_ctx->key) );
    return OAES_RET_MEM;
  }

  memcpy( _ctx->key->data, data, data_len );
  _rc = _rc || oaes_key_expand( ctx );
  
  if( _rc != OAES_RET_SUCCESS )
  {
    oaes_key_destroy( &(_ctx->key) );
    return _rc;
  }
  
  return OAES_RET_SUCCESS;
}

OAES_CTX * oaes_alloc()
{
  oaes_ctx * _ctx = (oaes_ctx *) calloc( sizeof( oaes_ctx ), 1 );
  
  if( NULL == _ctx )
    return NULL;

#ifdef OAES_HAVE_ISAAC
  {
    ub4 _i = 0;
    char _seed[RANDSIZ + 1];
    
    _ctx->rctx = (randctx *) calloc( sizeof( randctx ), 1 );

    if( NULL == _ctx->rctx )
    {
      free( _ctx );
      return NULL;
    }
	
    oaes_get_seed( _seed );
    memset( _ctx->rctx->randrsl, 0, RANDSIZ );
    memcpy( _ctx->rctx->randrsl, _seed, RANDSIZ );
    randinit( _ctx->rctx, TRUE);
  }
#else
    srand( oaes_get_seed() );
#endif // OAES_HAVE_ISAAC

  _ctx->key = NULL;
  oaes_set_option( _ctx, OAES_OPTION_CBC, NULL );

#ifdef OAES_DEBUG
  _ctx->step_cb = NULL;
  oaes_set_option( _ctx, OAES_OPTION_STEP_OFF, NULL );
#endif // OAES_DEBUG

  return (OAES_CTX *) _ctx;
}

OAES_RET oaes_free( OAES_CTX ** ctx )
{
  oaes_ctx ** _ctx = (oaes_ctx **) ctx;

  if( NULL == _ctx )
    return OAES_RET_ARG1;
  
  if( NULL == *_ctx )
    return OAES_RET_SUCCESS;
  
  if( (*_ctx)->key )
    oaes_key_destroy( &((*_ctx)->key) );

#ifdef OAES_HAVE_ISAAC
  if( (*_ctx)->rctx )
  {
    free( (*_ctx)->rctx );
    (*_ctx)->rctx = NULL;
  }
#endif // OAES_HAVE_ISAAC
  free( *_ctx );
  *_ctx = NULL;

  return OAES_RET_SUCCESS;
}

OAES_RET oaes_set_option( OAES_CTX * ctx,
    OAES_OPTION option, const void * value )
{
  size_t _i;
  oaes_ctx * _ctx = (oaes_ctx *) ctx;
  
  if( NULL == _ctx )
    return OAES_RET_ARG1;

  switch( option )
  {
    case OAES_OPTION_ECB:
      _ctx->options &= ~OAES_OPTION_CBC;
      memset( _ctx->iv, 0, OAES_BLOCK_SIZE );
      break;

    case OAES_OPTION_CBC:
      _ctx->options &= ~OAES_OPTION_ECB;
      if( value )
        memcpy( _ctx->iv, value, OAES_BLOCK_SIZE );
      else
      {
        for( _i = 0; _i < OAES_BLOCK_SIZE; _i++ )
          _ctx->iv[_i] = (uint8_t) OAES_RAND(_ctx->rctx);
      }
      break;

#ifdef OAES_DEBUG

    case OAES_OPTION_STEP_ON:
      if( value )
      {
        _ctx->options &= ~OAES_OPTION_STEP_OFF;
        _ctx->step_cb = value;
      }
      else
      {
        _ctx->options &= ~OAES_OPTION_STEP_ON;
        _ctx->options |= OAES_OPTION_STEP_OFF;
        _ctx->step_cb = NULL;
        return OAES_RET_ARG3;
      }
      break;

    case OAES_OPTION_STEP_OFF:
      _ctx->options &= ~OAES_OPTION_STEP_ON;
      _ctx->step_cb = NULL;
      break;

#endif // OAES_DEBUG

    default:
      return OAES_RET_ARG2;
  }

  _ctx->options |= option;

  return OAES_RET_SUCCESS;
}

OAES_RET oaes_encrypt( OAES_CTX * ctx,
    const uint8_t * m, size_t m_len, uint8_t * c, size_t * c_len,
    uint8_t iv[OAES_BLOCK_SIZE], uint8_t * pad )
{
  size_t _i, _j, _c_len_in;
  char *_buf;
  size_t _buf_len;
  size_t _pad_len = m_len % OAES_BLOCK_SIZE == 0 ?
      0 : OAES_BLOCK_SIZE - m_len % OAES_BLOCK_SIZE;
  oaes_ctx * _ctx = (oaes_ctx *) ctx;
  OAES_RET _rc = OAES_RET_SUCCESS;
  
  if( NULL == _ctx )
    return OAES_RET_ARG1;
  
  if( NULL == m )
    return OAES_RET_ARG2;
  
  if( NULL == c_len )
    return OAES_RET_ARG5;
  
  _c_len_in = *c_len;
  // data + pad
  *c_len = m_len + _pad_len;

  if( NULL == c )
    return OAES_RET_SUCCESS;
  
  if( _c_len_in < *c_len )
    return OAES_RET_BUF;
  
  if( NULL == iv )
    return OAES_RET_ARG6;

  if( NULL == pad )
	  return OAES_RET_ARG7;

  if (NULL == _ctx->key)
    return OAES_RET_NOKEY;
  
  *pad = _pad_len ? 1 : 0;
  memcpy(c, m, m_len );
 
	
  uint8_t *vi = (uint8_t *) malloc(OAES_BLOCK_SIZE * sizeof(uint8_t)); 
  int i;
  for(i=0; i<OAES_BLOCK_SIZE; i++){
	vi[i] = _ctx->iv[i];
  }  
  oaes_key *g_key = _ctx->key;
  OAES_OPTION opt = _ctx->options;
   
  #ifdef OAES_HAVE_ISAAC
  r_rctx = _ctx->rctx;
  #endif

  #ifdef OAES_DEBUG
  r_step_cb = _ctx->step_cb;
  #endif

 
  func(c_len, c, &m_len, &_rc, &_ctx);					//cuda file C function call	


  #ifdef OAES_HAVE_ISAAC
  _ctx->rctx = r_rctx;
  #endif
 
  #ifdef OAES_DEBUG
  _ctx->step_cb = r_step_cb;
  #endif

  _ctx->key = g_key;
  _ctx->options = opt; 
  for(i=0; i<OAES_BLOCK_SIZE; i++){
	_ctx->iv[i] = vi[i];
  } 
  free(vi); 
  return _rc;
}

OAES_RET oaes_decrypt( OAES_CTX * ctx,
    const uint8_t * c, size_t c_len, uint8_t * m, size_t * m_len,
    uint8_t iv[OAES_BLOCK_SIZE], uint8_t pad)
{
  size_t _i, _j, _m_len_in;
  int i;
  oaes_ctx * _ctx = (oaes_ctx *) ctx;
  OAES_RET _rc = OAES_RET_SUCCESS;
  uint8_t _flags;
  OAES_OPTION _options;
  
  if( NULL == ctx )
    return OAES_RET_ARG1;
  
  if( NULL == c )
    return OAES_RET_ARG2;
  
  if( c_len % OAES_BLOCK_SIZE )
    return OAES_RET_ARG3;
  
  if( NULL == m_len )
  {
	  return OAES_RET_ARG5;
  }

  
  _m_len_in = *m_len;
  *m_len = c_len;

  if( NULL == m )
  {
	  return OAES_RET_SUCCESS;
  }
	
  if( _m_len_in < *m_len )
  {
	  printf("Decrypt: mlen problem!\n");
    return OAES_RET_BUF;
  }

  if (NULL == iv)
	  {
	  printf("Decrypt: iv problem!\n");
		return OAES_RET_ARG6;
	  }

  if (NULL == _ctx->key)
	{
	  printf("Decrypt: fucking key problem!\n");
    return OAES_RET_NOKEY;
	}

  // options
  _options = _ctx->options;

  // validate that all options are valid

	
  if( _options & ~(
        OAES_OPTION_ECB
      | OAES_OPTION_CBC
#ifdef OAES_DEBUG
      | OAES_OPTION_STEP_ON
      | OAES_OPTION_STEP_OFF
#endif // OAES_DEBUG 
      ) )
	  {
		return OAES_RET_HEADER;
	}
  if( ( _options & OAES_OPTION_ECB ) &&
      ( _options & OAES_OPTION_CBC ) )
	{
		return OAES_RET_HEADER;
	}
  if( _options == OAES_OPTION_NONE )
  {
    return OAES_RET_HEADER;
	}

  memcpy(m, c, *m_len);

  OAES_RET pad_check = OAES_RET_SUCCESS;
  oaes_key *g_key = _ctx->key;
  OAES_OPTION opt = _ctx->options;

 #ifdef OAES_HAVE_ISAAC
  r_rctx = _ctx->rctx;
  #endif
	

  #ifdef OAES_DEBUG
  r_step_cb = _ctx->step_cb;
  #endif

  func2(m, m_len, &_rc, &_ctx, &pad, &pad_check);	


 #ifdef OAES_HAVE_ISAAC
  _ctx->rctx = r_rctx;
  #endif
 

  #ifdef OAES_DEBUG
  _ctx->step_cb = r_step_cb;
  #endif

  _ctx->key = g_key;
  _ctx->options = opt; 

  
  if(pad_check != OAES_RET_SUCCESS)
  {
  		return pad_check;
  }
  else
  {
		return _rc;
  }
}
