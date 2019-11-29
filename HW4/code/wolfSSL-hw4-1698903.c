#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <assert.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

#define AES_BLOCK_SIZE 16   //128 bits
//to compile: gcc wolfSSL-hw4-1698903.c -o wolfSSL -lm -lwolfssl

void handleErrors(void){
    printf("Errors during operations\n");
    abort();
}

int main (int argc, char **argv)
{
  if(argc < 2){
    printf("Please insert the name of the file to use for the test\n");
    exit(1);
  }

  printf("READING FILE... ");
	unsigned char* in;													// Structure for the input file
	unsigned long in_size;
	char* filename = argv[1];

	int fd = open(filename, O_RDONLY, (mode_t)0666);
	int fdr = fd;
	if(fd == -1) fprintf(stderr, "Error while opening the file\n");
	in_size = lseek(fd, 0, SEEK_END);
	in = malloc(sizeof(char)*in_size);
	in = (unsigned char*) mmap(0, in_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fdr, 0);
	close(fdr);
  //printf("%s\n", in);

	printf(" COMPLITED \n");
  printf("FILE LENGTH = %ld Bytes\n\n", strlen((char*)in));


  //Structures for the cipher
  unsigned char* key_256 = malloc(sizeof(char)*32);
	unsigned char* iv_128 = malloc(sizeof(char)*16);
	unsigned char* aux_iv_128 = malloc(sizeof(char)*16);
	clock_t start, end;
	double enc_time = 0, dec_time = 0;

  //initialization
  RNG  rngk;
  if (wc_InitRng(&rngk) != 0)
  if (wc_RNG_GenerateBlock(&rngk, key_256, 32) != 0)
    handleErrors();

  RNG  rngiv;
  if (wc_InitRng(&rngiv) != 0)
  if (wc_RNG_GenerateBlock(&rngiv, iv_128, 16) != 0)
      handleErrors();


  int text_size = ((in_size/AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;  //because CBC adds length
  unsigned char * ciphertext = malloc((sizeof(char)*text_size));;
  unsigned char * plaintext = malloc((sizeof(char)*text_size));;

  //start operations
  Aes enc;
  if (wc_AesSetKey(&enc, key_256, 32, iv_128, AES_ENCRYPTION) != 0)
    handleErrors();
  memcpy(aux_iv_128, iv_128, AES_BLOCK_SIZE);   //because of the side effect produced by CBC
  start = clock();
  if (wc_AesCbcEncrypt(&enc, ciphertext, in, in_size) != 0)
    handleErrors();
  end = clock();
  enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
  printf("  ENCRYPTION TIME = %lf\n", enc_time);

  Aes dec;
  if (wc_AesSetKey(&dec, key_256, 32, iv_128, AES_DECRYPTION) != 0)
    handleErrors();
  memcpy(aux_iv_128, iv_128, AES_BLOCK_SIZE);
  start = clock();
  if (wc_AesCbcDecrypt(&dec, plaintext, ciphertext, text_size) != 0) handleErrors();
    plaintext[in_size] = '\0';
  end = clock();
  dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
  printf("  DECRYPTIION TIME = %lf\n", dec_time);

  printf("  SPEED RATIO => %lf\n\n", (enc_time/dec_time));
  //printf("ciphertext = %s \n\nplaintext = %s\n", ciphertext, plaintext);

  free(ciphertext);
  free(plaintext);
  free(key_256);
	free(iv_128);
	free(aux_iv_128);

  return 0;
}
