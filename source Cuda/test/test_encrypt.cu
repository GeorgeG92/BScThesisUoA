/* 
 * ---------------------------------------------------------------------------
 * OpenAES License
 * ---------------------------------------------------------------------------
 * Copyright (c) 2012, Nabil S. Al Ramli, www.nalramli.com
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * ---------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../inc/oaes_base64.h"
#include "../inc/oaes_config.h"

#include "../inc/oaes_lib.h"
#include "../inc/oaes_common.h"
#include "../src/isaac/rand.h"

#define NEXT_BLOCK 8000
 
int Memtime_enc; 
int Memtime_dec;
int kernel_time;
 
 extern OAES_RET oaes_base64_encode(const uint8_t *in, size_t in_len, char *out, size_t *out_len);
 extern OAES_RET oaes_base64_decode(const char *in, size_t in_len, uint8_t *out, size_t *out_len );
 

void usage(const char * exe_name)
{
  if( NULL == exe_name )
    return;
  
  printf(
      "Usage:\n"
      "\t%s [-ecb] [-key < 128 | 192 | 256 >] <text>\n",
      exe_name
  );
}

void file_error(char *filename)
{
	if( NULL == filename )
	{
		return;
	}
	printf("I/O error:\n"
      "\tFile '%s' doesn't exist or is inaccessible\n",
      filename);
}

int main(int argc, char** argv)
{
	//=================================================================================//declare variables//=================================================================================//
  size_t _i;
  OAES_CTX * ctx = NULL;
  uint8_t *_encbuf, *_decbuf;
  size_t _encbuf_len, _decbuf_len, _buf_len;
  char *_buf;
  char **_buf_pl_begin;
  char **_buf_pl_end;
  short _is_ecb = 0;
  char ** _text = NULL;
  int _key_len = 128;
  uint8_t _iv[OAES_BLOCK_SIZE] = "";
  uint8_t _pad = 0;
  int count= 0 ;
  int blocks;

   //=========================================================================//handle allocations and arguments(key size, mode, data size, file name)//================================================================================//
  if( argc < 2 )
  {
    usage( argv[0] );
    return EXIT_FAILURE;
  }

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
      _i++; // len
      if( _i >= argc )
      {
        printf("Error: No value specified for '-%s'.\n",
            "key");
        usage( argv[0] );
        return EXIT_FAILURE;
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
          return EXIT_FAILURE;
      }
    }
    
    if( 0 == _found )
    {
      if( _text )
      {
        printf("Error: Invalid option '%s'.\n", argv[_i]);
        usage( argv[0] );
        return EXIT_FAILURE;
      }
      else
      {
        char c;
        FILE *fp = fopen(argv[_i], "r");
		if (fp == NULL)						//check file existance and integrity
		{
			file_error(argv[_i]);
			return EXIT_FAILURE;
		}
        while((c=fgetc(fp))) {

			/* break if end of file */
			if(c == EOF) 
			  break;

			/* otherwise add one to the count of that particular character */
					
			count +=1;
        }
		fclose(fp);        
		
		if(count%NEXT_BLOCK==0)
		{
			blocks = count/NEXT_BLOCK;
		}
		else
		{
			blocks = (count/NEXT_BLOCK)+1;
		}
		
		int l;
		_buf_pl_begin = (char **) calloc (blocks, sizeof(char*));
		_buf_pl_end = (char **) calloc (blocks, sizeof(char*));
		_text = (char **) calloc (blocks, sizeof(char*));
		for(l=0; l<blocks; l++){
			if(l == blocks - 1){
				_text[l] = (char *)  calloc (count - ((blocks-1)*NEXT_BLOCK) , sizeof(char));
			}
			else{
				_text[l] = (char *)  calloc (NEXT_BLOCK , sizeof(char));
			}
		}
		
        if( NULL == _text )
        {
          printf("Error: Failed to allocate memory %s.\n", argv[_i]);
          return EXIT_FAILURE;
        }
       
		int k;
		fp = fopen(argv[_i], "r");
        for(l=0; l<blocks; l++){
		    if(l == blocks - 1)
			{
				for(k=0; k<(count - ((blocks-1)*NEXT_BLOCK)); k++)
					_text[l][k] = fgetc(fp);
			}
			else{
				for(k=0; k<NEXT_BLOCK; k++)
					_text[l][k] = fgetc(fp);
			}		
        }
        fclose(fp);        
      }
    }      
  }																						

  if( NULL == _text )
  {
    usage( argv[0] );
    return EXIT_FAILURE;
  }
  
  //=================================================================================//display initial plaintext and initialize variables//=================================================================================//
  int l;
    printf( "\n***** plaintext  *****\n" );																//Print plaintext before encryption (all 8000char lines)
	
	for(l=0; l<blocks; l++)
	{
		  oaes_sprintf( NULL, &_buf_len,
			  (const uint8_t *)_text[l], strlen( _text[l]) );
		  _buf_pl_begin[l] = (char *) calloc(_buf_len, sizeof(char));
		  if( _buf_pl_begin[l] )
		  {
			oaes_sprintf( _buf_pl_begin[l], &_buf_len,
				(const uint8_t *)_text[l], strlen( _text[l] ) );
			printf( "%s", _buf_pl_begin[l] );
		  }
	} 
	
	printf( "\n**********************\n" );
  
  ctx = oaes_alloc();
  if( NULL == ctx )
  {
    printf("Error: Failed to initialize OAES.\n");
    int g;
	for(g=0; g<blocks; g++)
		free( _text[g]);
	free(_text);
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

  
  //=================================================================================//encr/decr of data with prints//=================================================================================//
  for(l=0; l<blocks; l++)
  {
	  if( OAES_RET_SUCCESS != oaes_encrypt( ctx,
		  (const uint8_t *)_text[l], strlen( _text[l] ), NULL, &_encbuf_len,NULL, NULL ) )	
		  {															//set _encbuf_len
			printf("Error: Failed to retrieve required buffer size for encryption.\n");
			}
	  _encbuf = (uint8_t *) calloc( _encbuf_len, sizeof(uint8_t) );
	  if( NULL == _encbuf )
	  {
		printf( "Error: Failed to allocate memory.\n" );
		int g;
		for(g=0; g<blocks; g++)
			free( _text[g]);
		free(_text);	
		return EXIT_FAILURE;
	  }
	  memcpy(_iv, "1234567890123456", OAES_BLOCK_SIZE);
	  if( OAES_RET_SUCCESS != oaes_encrypt( ctx,
		  (const uint8_t *)_text[l], strlen( _text[l] ), _encbuf, &_encbuf_len,
		  _iv, &_pad ) )														//encr 2
		printf("Error: Encryption failed.\n");
		
		
		 printf( "\n***** cyphertext part %d/%d *****\n", l+1, blocks);
	  oaes_sprintf( NULL, &_buf_len, _encbuf, _encbuf_len );							
	  _buf = (char *) calloc(_buf_len, sizeof(char));
	  if( _buf )
	  {
		oaes_sprintf( _buf, &_buf_len, _encbuf, _encbuf_len );						
		printf( "%s", _buf );
	  }
	  printf( "\n**********************\n" );
	  free( _buf );
	

	  if( OAES_RET_SUCCESS != oaes_decrypt( ctx,
		  _encbuf, _encbuf_len, NULL, &_decbuf_len, NULL, NULL ) )		
		 {
		printf("Error: Failed to retrieve required buffer size for encryption.\n");
		}
	  _decbuf = (uint8_t *) calloc( _decbuf_len, sizeof(uint8_t) );
	  
	  if( NULL == _decbuf )
	  {
		printf( "Error: Failed to allocate memory.\n" );
		int g;
		for(g=0; g<blocks; g++)
			free( _text[g]);
		free(_text);	
		free( _encbuf );
		return EXIT_FAILURE;
	  }
	  memcpy(_iv, "1234567890123456", OAES_BLOCK_SIZE);
	  
	  
	  if( OAES_RET_SUCCESS != oaes_decrypt( ctx,							
		  _encbuf, _encbuf_len, _decbuf, &_decbuf_len, _iv, _pad ) )
		printf("Error: Decryption failed.\n");

	  
	  oaes_sprintf( NULL, &_buf_len, _decbuf, _decbuf_len );							
	  _buf_pl_end[l] = (char *) calloc(_buf_len, sizeof( char));
	  
	  
	  if( _buf_pl_end[l] )
	  {
		oaes_sprintf( _buf_pl_end[l], &_buf_len, _decbuf, _decbuf_len );			
	  }
	  
	 free( _encbuf );
     free( _decbuf );
   }
   
   /////////////////////////////
   printf( "\n***** plaintext  *****\n" );																//Print plaintext before encryption (all 8000char lines)
	
	for(l=0; l<blocks; l++)
	{
		  oaes_sprintf( NULL, &_buf_len,
			  (const uint8_t *)_text[l], strlen( _text[l]) );
		  _buf_pl_end[l] = (char *) calloc(_buf_len, sizeof(char));
		  if( _buf_pl_end[l] )
		  {
			oaes_sprintf( _buf_pl_end[l], &_buf_len,
				(const uint8_t *)_text[l], strlen( _text[l] ) );
			printf( "%s", _buf_pl_end[l] );
		  }
	} 
	
	printf( "\n**********************\n" );
   
   
   //=================================================================================//clean up and verification//=================================================================================//
   if( OAES_RET_SUCCESS !=  oaes_free( &ctx ) )
		printf("Error: Failed to uninitialize OAES.\n");

	printf("Number of buffers = %d\n", blocks);
	int *equal = (int *) malloc(blocks * sizeof(int));
    int g = 0;
	for(g=0; g<blocks; g++){
		equal[g] = 0;
	}
	
	for(g=0; g<blocks; g++){
		if(strcmp(_buf_pl_begin[g], _buf_pl_end[g]) != 0){
			equal[g] = 1;
		}
	}
	
	int verflag=0;
	for(g=0; g<blocks; g++)																//check all 8000char pieces for verification
	{
		int size1;
		int size2;
		if(equal[g] == 1)
		{
			printf("Verification FAILED: the decrypted file doesn't match the input file! \n");
			verflag=1;
			break;
		}	
	}
	if (verflag==0)
	{
		printf("Verification SUCCESS: the decrypted file matches the input file! \n");
	}
	
	for(g=0; g<blocks; g++){
		free( _text[g]);
		free(_buf_pl_begin[g]);
		free(_buf_pl_end[g]);
	}
	free(_text);
	free(_buf_pl_begin);
	free(_buf_pl_end);	
	free(equal);
  return (EXIT_SUCCESS);
}
