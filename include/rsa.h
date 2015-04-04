#ifndef __RSA_H__
#define __RSA_H__

#include <stdbool.h>

#define RSA_BLOCK_SIZE 256

int rsa_key_check(char *key, int key_len, bool is_public_key);
int public_encrypt(char *data, int data_len, char *public_key, int key_len, char *encrypted);
int private_decrypt(char *enc_data, int data_len, char *key, int key_len, char *decrypted);

#endif
