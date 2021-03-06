#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/timeb.h>

#include "../inc/oaes_lib.h"

int Memtime_enc;
int Memtime_dec;
int kernel_time;

void usage(const char * exe_name)
{
  if( NULL == exe_name )
    return;
  
  printf(
      "Usage:\n"
      "\t%s [-ecb] [-key < 128 | 192 | 256 >] [-data <data_len>]\n",
      exe_name
  );
}

/*
 * 
 */
int main(int argc, char** argv) 
{
  //=================================================================================//declare variables//=================================================================================//
  Memtime_enc=0;
  Memtime_dec=0;
  kernel_time=0;
  size_t _i, _j;
  struct timeb start, end, initend, encstart, decstart, encend, decend;
  OAES_CTX * ctx = NULL;
  uint8_t *_encbuf, *_decbuf;
  size_t _encbuf_len, _decbuf_len;
  uint8_t _buf[1024 * 1024];
  short _is_ecb = 0;
  int _key_len = 128;
  size_t _data_len = 64;
  uint8_t _iv[OAES_BLOCK_SIZE] = "";
  uint8_t _pad = 0;

  ftime(&start);
  cudaFree(0);															//force CUDA driver initialization and context creation!!!
  
  //=========================================================================//handle arguments (key size, mode, data size)//================================================================================//
  for( _i = 1; _i < argc; _i++ )
  {
    int _found = 0;
    
    if( 0 == strcmp( argv[_i], "-ecb" ) )
    {
      _found = 1;
      _is_ecb = 1;
    }
    
    if( 0 == strcmp( argv[_i], "-key" ) )
    {
      _found = 1;
      _i++; // key_len
      if( _i >= argc )
      {
        printf("Error: No value specified for '-%s'.\n",
            "key");
        usage( argv[0] );
        return 1;
      }
      _key_len = atoi( argv[_i] );
      switch( _key_len )
      {
        case 128:
        case 192:
        case 256:
          break;
        default:
          printf("Error: Invalid value [%d] specified for '-%s'.\n",
              _key_len, "key");
          usage( argv[0] );
          return 1;
      }
    }
    
    if( 0 == strcmp( argv[_i], "-data" ) )
    {
      _found = 1;
      _i++; // data_len
      if( _i >= argc )
      {
        printf("Error: No value specified for '-%s'.\n",
            "data");
        usage( argv[0] );
        return 1;
      }
      _data_len = atoi( argv[_i] );
    }
    
    if( 0 == _found )
    {
      printf("Error: Invalid option '%s'.\n", argv[_i]);
      usage( argv[0] );
      return 1;
    }      
  }

  //=========================================================================//generate random test data//=================================================================================//
  for( _i = 0; _i < 1024 * 1024; _i++ )														//1MB buffer (1024x1024)
  {
    _buf[_i] = rand();
  }
  
  //=========================================================================//initialize oaes variables//=================================================================================//

  ctx = oaes_alloc();
  if( NULL == ctx )
  {
    printf("Error: Failed to initialize OAES.\n");
    return EXIT_FAILURE;
  }
  if( _is_ecb )
    if( OAES_RET_SUCCESS != oaes_set_option( ctx, OAES_OPTION_ECB, NULL ) )
      printf("Error: Failed to set OAES options.\n");
  switch( _key_len )
  {
    case 128:
      if( OAES_RET_SUCCESS != oaes_key_gen_128(ctx) )
        printf("Error: Failed to generate OAES %d bit key.\n", _key_len);
      break;
    case 192:
      if( OAES_RET_SUCCESS != oaes_key_gen_192(ctx) )
        printf("Error: Failed to generate OAES %d bit key.\n", _key_len);
      break;
    case 256:
      if( OAES_RET_SUCCESS != oaes_key_gen_256(ctx) )
        printf("Error: Failed to generate OAES %d bit key.\n", _key_len);
      break;
    default:
      break;
  }

  //=========================================================================//initialize buffer length (1MB)//=================================================================================//
  
  if( OAES_RET_SUCCESS != oaes_encrypt( ctx,
      (const uint8_t *)_buf, 1024 * 1024, NULL, &_encbuf_len, NULL, NULL ) )			//encbuf_len 1MB!
    printf("Error: Failed to retrieve required buffer size for encryption.\n");
  _encbuf = (uint8_t *) calloc( _encbuf_len, sizeof( char ) );							//calloc 1MB! 
  if( NULL == _encbuf )
  {
    printf( "Error: Failed to allocate memory.\n" );
    return EXIT_FAILURE;
  }

  if( OAES_RET_SUCCESS != oaes_decrypt( ctx,
      _encbuf, _encbuf_len, NULL, &_decbuf_len, NULL, NULL ) )							//decbuf_len 1MB!
    printf("Error: Failed to retrieve required buffer size for encryption.\n");
  _decbuf = (uint8_t *) calloc( _decbuf_len, sizeof( char ) );							//1MB!
  if( NULL == _decbuf )
  {
    free( _encbuf );
    printf( "Error: Failed to allocate memory.\n" );
    return EXIT_FAILURE;
  }
 
   ftime(&initend);
  //time( &_time_start );

  int enctime=0;
  int dectime=0;
  
  //=========================================================================//start encr/decr loop//=================================================================================//
  
  for( _i = 0; _i < _data_len; _i++ )													//MB = -data X !!!
  {
    memcpy(_iv, "123456789012345", OAES_BLOCK_SIZE);
	
	ftime(&encstart);

    if( OAES_RET_SUCCESS != oaes_encrypt( ctx, (const uint8_t *)_buf, 1024 * 1024, _encbuf, &_encbuf_len, _iv, &_pad ) )
	{
      printf("Error: Encryption failed.\n");
	}
	
	ftime(&encend);
	enctime+= (int) (1000.0 * (encend.time - encstart.time)+ (encend.millitm - encstart.millitm));
	
    memcpy(_iv, "123456789012345", OAES_BLOCK_SIZE);

	ftime(&decstart);
	
    if( OAES_RET_SUCCESS !=  oaes_decrypt( ctx, _encbuf, _encbuf_len, _decbuf, &_decbuf_len, _iv, _pad ) )
	{
      printf("Error: Decryption failed.\n");
	} 
	ftime(&decend);
	dectime+= (int) (1000.0 * (decend.time - decstart.time)+ (decend.millitm - decstart.millitm));
  }
  
  ftime(&end);
  int totaltime = (int) (1000.0 * (end.time - start.time)+ (end.millitm - start.millitm));
  //////////////////////////////////////////

  //=========================================================================//Free buffers and display results//=================================================================================//
  printf( "Test encrypt and decrypt:\n\ttime: %u ms\n\t\tInit Time: %u ms\n\t\tTotal Encrypton Time:%u ms\n\t\t\tMemoryOps: %u ms\n\t\tTotal Decryption Time:%u ms\n\t\t\tMemoryOps: %u ms\n\t\tKernel Time: %u ms\n\tdata: %ld MB"
      "\n\tkey: %d bits\n\tmode: %s\n",
      totaltime,
	  (int) (1000.0 * (initend.time - start.time)+ (initend.millitm - start.millitm)),
	  enctime, Memtime_enc, dectime, Memtime_dec, kernel_time,  _data_len,
      _key_len, _is_ecb? "ECB" : "CBC" );
  free( _encbuf );
  free( _decbuf );
  if( OAES_RET_SUCCESS !=  oaes_free( &ctx ) )
  {
    printf("Error: Failed to uninitialize OAES.\n");
  }
  
  return (EXIT_SUCCESS);
}
