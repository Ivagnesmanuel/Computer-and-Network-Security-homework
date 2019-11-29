#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <assert.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/modes.h>

#define AES_BLOCK_SIZE 16   //128 bits

void handleErrors(void){
    ERR_print_errors_fp(stderr);
    abort();
}


//OpenSSL wiki function for standard symmetric encryption
int enc(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


//OpenSSL wiki function for standard symmetric decryption
int dec(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}


//OpenSSL wiki function for GCM authenticated encryption
int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

        //aad removed

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


//OpenSSL wiki function for GCM authenticated decryption
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

        //aad removed

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
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
  unsigned char tag[16];
	unsigned char* aux_iv_128 = malloc(sizeof(char)*16);
	clock_t start, end;
	double enc_time = 0, dec_time = 0;
	int i = 0;

  //initialization
  RAND_bytes(key_256, 32);
	RAND_bytes(iv_128, AES_BLOCK_SIZE);



  printf("######## Operating Mode: CBC ########\n");
  int text_size = ((in_size/AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;  //because CBC adds length
  unsigned char * ciphertext = malloc((sizeof(char)*text_size));;
  unsigned char * plaintext = malloc((sizeof(char)*text_size));;

  memcpy(aux_iv_128, iv_128, AES_BLOCK_SIZE);   //because of the side effect produced by CBC
  start = clock();
  int ciphertext_len = enc(in, strlen ((char *)in), key_256, aux_iv_128, ciphertext);
  end = clock();
  enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
  printf("  ENCRYPTION TIME = %lf\n", enc_time);

  memcpy(aux_iv_128, iv_128, AES_BLOCK_SIZE);
  start = clock();
  int decryptedtext_len = dec(ciphertext, ciphertext_len, key_256, aux_iv_128, plaintext);
  end = clock();
  dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
  printf("  DECRYPTIION TIME = %lf\n", dec_time);

  printf("  SPEED RATIO => %lf\n\n", (enc_time/dec_time));
  plaintext[decryptedtext_len] = '\0';


  //printf("ciphertext = %s \n\nplaintext = %s\n", ciphertext, plaintext);
  printf("  ciphertext_len = %d, decryptedtext_len = %d\n\n", ciphertext_len, decryptedtext_len);

  free(ciphertext);
  free(plaintext);


  ciphertext = malloc((sizeof(char)*in_size));;
  plaintext = malloc((sizeof(char)*in_size));;

  printf("######## Operating Mode: GCM ########\n");
  memcpy(aux_iv_128, iv_128, AES_BLOCK_SIZE);
	start = clock();
	ciphertext_len = gcm_encrypt(in, strlen ((char *)in), NULL, 0, key_256, aux_iv_128, AES_BLOCK_SIZE, ciphertext, tag);
	end = clock();
	enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("  ENCRYPTION TIME = %lf\n", enc_time);

	start = clock();
	decryptedtext_len = gcm_decrypt(ciphertext, ciphertext_len, NULL, 0, tag, key_256, iv_128, AES_BLOCK_SIZE, plaintext);
	end = clock();
	dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
  if (decryptedtext_len == -1)
    printf("  DECRYPTIION failed\n");
  else{
    printf("  DECRYPTIION TIME = %lf\n", dec_time);
	  printf("  SPEED RATIO => %lf\n\n", (enc_time/dec_time));
    plaintext[decryptedtext_len] = '\0';

    //printf("ciphertext = %s \n\nplaintext = %s\n", ciphertext, plaintext);
    printf("  ciphertext_len = %d, decryptedtext_len = %d\n\n", ciphertext_len, decryptedtext_len);
  }

  free(ciphertext);
  free(plaintext);
  free(key_256);
	free(iv_128);
	free(aux_iv_128);

  return 0;
}
