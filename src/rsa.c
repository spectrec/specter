#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "rsa.h"
#include "log.h"

static int padding = RSA_PKCS1_PADDING;

#define PUBLIC_KEY_SIZE 451
#define PRIVATE_KEY_SIZE 1675

#define RSA_MAX_SIZE_TO_DECRYPT(_rsa) (RSA_size(_rsa))
#define RSA_MAX_SIZE_TO_ENCRYPT(_rsa) (RSA_size(_rsa) - 11)

static void rsa_cleanup_bio(BIO **bio)
{
	if (*bio != NULL)
		BIO_free(*bio);
}

static RSA *rsa_create_rsa(char *key, int key_len, bool is_public)
{
	RSA *rsa = NULL;
	BIO *bio __attribute__((cleanup(rsa_cleanup_bio))) = NULL;

	if ((bio = BIO_new_mem_buf(key, key_len)) == NULL) {
		log_e("failed to create key BIO");
		return NULL;
	}

	rsa = is_public == true
		? PEM_read_bio_RSA_PUBKEY(bio, &rsa, NULL, NULL)
		: PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);

	if (rsa == NULL) {
		log_e("failed to create RSA");
		return NULL;
	}

	return rsa;
}

int rsa_key_check(char *key, int len, bool is_public_key)
{
	RSA *rsa = rsa_create_rsa(key, len, is_public_key);

	if (rsa != NULL) {
		RSA_free(rsa);

		return 0;
	}

	return -1;
}

int public_encrypt(char *data, int data_len, char *public_key,
		   int key_len, char *encrypted)
{
	RSA *rsa = rsa_create_rsa(public_key, key_len, true);
	int ret;

	if (rsa == NULL)
		return -1;

	assert(data_len < RSA_MAX_SIZE_TO_ENCRYPT(rsa));
	ret = RSA_public_encrypt(data_len, (unsigned char *)data,
				 (unsigned char *)encrypted, rsa, padding);
	RSA_free(rsa);

	return ret;
}

int private_decrypt(char *enc_data, int data_len, char *key,
		    int key_len, char *decrypted)
{
	RSA *rsa = rsa_create_rsa(key, key_len, false);
	int ret;

	if (rsa == NULL)
		return -1;

	assert(data_len <= RSA_MAX_SIZE_TO_DECRYPT(rsa));
	ret = RSA_private_decrypt(data_len, (unsigned char *)enc_data,
				  (unsigned char *)decrypted, rsa, padding);
	RSA_free(rsa);

	return ret;
}


__attribute__((destructor))
static void rsa_cleanup(void)
{
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	ERR_remove_state(0);
	EVP_cleanup();
}
