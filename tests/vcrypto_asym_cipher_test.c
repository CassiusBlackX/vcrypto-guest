#include <assert.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/types.h>

#include <log.h>

#ifndef CMAKE_CURRENT_SOURCE_PATH
#define CMAKE_CURRENT_SOURCE_PATH ".."
#endif
#define PUBLIC_KEY_PATH "public.pem"
#define PRIVATE_KEY_PATH "private.pem"

int main(int argc, char **argv) {
  log_set_level(LOG_TRACE);
  int ret;
  char pubkey_path[256];
  snprintf(pubkey_path, sizeof(pubkey_path), "%s/%s", CMAKE_CURRENT_SOURCE_PATH,
           PUBLIC_KEY_PATH);
  printf("pub_key_path: %s\n", pubkey_path);
  char privkey_path[256];
  snprintf(privkey_path, sizeof(privkey_path), "%s/%s", CMAKE_CURRENT_SOURCE_PATH,
           PRIVATE_KEY_PATH);
  printf("priv_key_path: %s\n", privkey_path);

  // load public key and private key
  FILE *fp_pub = fopen(pubkey_path, "r");
  assert(fp_pub && "failed to open public key path");
  EVP_PKEY *pubkey = PEM_read_PUBKEY(fp_pub, NULL, NULL, NULL);
  assert(pubkey && "failed to read public key");
  fclose(fp_pub);
  FILE *fp_priv = fopen(privkey_path, "r");
  assert(fp_priv && "failed to open private key path");
  EVP_PKEY *privkey = PEM_read_PrivateKey(fp_priv, NULL, NULL, NULL);
  assert(privkey && "failed to read private key");
  fclose(fp_priv);

  // prepare plaintext
  const unsigned char plaintext[] = "Hello vCrypto Provider";
  printf("original plain text:\n");
  printf("%s\n", plaintext);
  size_t plaintext_len = sizeof(plaintext);

  // load provider
  OSSL_PROVIDER *prov_vcrypto = OSSL_PROVIDER_load(NULL, "vcrypto");
  assert(prov_vcrypto && "failed to load prov_vcrypto");
  log_trace("successfully loaded vcrypto provider for openssl");

  // fetch cipher
  EVP_PKEY_CTX *enc_ctx =
      EVP_PKEY_CTX_new_from_pkey(NULL, pubkey, "provider=vcrypto");
  assert(enc_ctx && "failed to create encrytion context");
  ret = EVP_PKEY_encrypt_init(enc_ctx);
  assert(ret > 0 && "failed to create encrytion context");

  ret = EVP_PKEY_encrypt_init(enc_ctx);
  assert(ret > 0 && "EVP_PKEY_encrypt_init failed");

  // padding
  size_t ciphertext_len;
  ret = EVP_PKEY_encrypt(enc_ctx, NULL, &ciphertext_len, plaintext,
                         plaintext_len);
  assert(ret > 0 && "failed to get ciphertext length");
  unsigned char *ciphertext = malloc(ciphertext_len);
  assert(ciphertext && "failed to malloc for ciphertext");

  // encrypt
  ret = EVP_PKEY_encrypt(enc_ctx, ciphertext, &ciphertext_len, plaintext,
                         plaintext_len);
  assert(ret > 0 && "failed to encrypt");
  log_trace("RSA encryption successful, ciphertext len = %zu", ciphertext_len);

  // create decrypt ctx
  EVP_PKEY_CTX *dec_ctx =
      EVP_PKEY_CTX_new_from_pkey(NULL, privkey, "provider=vcrypto");
  assert(dec_ctx && "failed to create decypt context");
  ret = EVP_PKEY_decrypt_init(dec_ctx);
  assert(ret > 0 && "EVP_PKEY_decrypt_init failed");

  // decrypt
  size_t decrypted_len;
  ret = EVP_PKEY_decrypt(dec_ctx, NULL, &decrypted_len, ciphertext,
                         ciphertext_len);
  assert(ret > 0 && "failed to get decrypted length");
  unsigned char *decrypted = malloc(decrypted_len);
  assert(decrypted && "failed to malloc for decrypted");
  ret = EVP_PKEY_decrypt(dec_ctx, decrypted, &decrypted_len, ciphertext,
                         ciphertext_len);
  assert(ret > 0 && "EVP_PKEY_decrypt failed");
  log_trace("RSA decryption successful, decrypted_len = %zu", decrypted_len);

  // output
  printf("decrypted text:\n%.*s\n", (int)decrypted_len, decrypted);

  // cleanup
  free(ciphertext);
  free(decrypted);
  EVP_PKEY_CTX_free(enc_ctx);
  EVP_PKEY_CTX_free(dec_ctx);
  EVP_PKEY_free(pubkey);
  EVP_PKEY_free(privkey);
  OSSL_PROVIDER_unload(prov_vcrypto);
  return 0;
}
