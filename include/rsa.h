#ifndef __RSA_H__
#define __RSA_H__

#define RSA_BLOCK_SIZE 256

int public_encrypt(char *data, int data_len, char *public_key, char *encrypted);
int public_decrypt(char *enc_data, int data_len, char *key, char *decrypted);
int private_decrypt(char *enc_data, int data_len, char *key, char *decrypted);
int private_encrypt(char *data, int data_len, char *key, char *encrypted);

#endif
