#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/types.h>
#include <openssl/err.h>

#include <log.h>

#ifndef PROJECT_BUILD_DIR
#define PROJECT_BUILD_DIR ".."
#endif

int main(int argc, char** argv) {
  log_set_level(LOG_TRACE);
  char provider_path[256];
  snprintf(provider_path, sizeof(provider_path), "%s/%s", PROJECT_BUILD_DIR, "./frontend");
  int ret;
  // int ret = setenv("OPENSSL_MODULES", provider_path, 1);
  // assert(ret == 0 && "failed to set env");
  // const char* openssl_modules_val = getenv("OPENSSL_MODULES");
  // if (openssl_modules_val) {
  //   log_trace("success set env OPENSSL_MODULES: %s", openssl_modules_val);
  // } else {
  //   log_warn("failed to set OPENSSL_MODULES env");
  // }

  const unsigned char plaintext[] = "Hello vCrypto Provider";
  size_t plaintext_len = sizeof(plaintext);

  unsigned char key[32] = {0};
  unsigned char iv[16] = {0};

  OSSL_PROVIDER *prov_vcrypto = OSSL_PROVIDER_load(NULL, "vcrypto");
  assert(prov_vcrypto && "failed to load prov_vcrypto");
  log_trace("successfully loaded vcrypto provider for openssl");

  EVP_CIPHER* cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", "provider=vcrypto");
  log_trace("EVP_CIPHER_fetch returned");
  if (!cipher) {
    unsigned long err = 0;
    while ((err = ERR_get_error()) != 0) {
      char buf[256];
      ERR_error_string_n(err, buf, sizeof(buf));
      log_error("openssl error: %s", buf);
    }
  }
  assert(cipher && "failed to fetch aes-256-cbc cipher using vcrypto provider");
  log_trace("successfully fetched aes-256-cbc cipher using vcrypto provider");

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  assert(ctx && "failed to new EVP_CIPHER_CTX");
  log_trace("EVP_CIPHER_CTX_new success");

  ret = EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL);
  assert(ret && "EVP_EncryptInit_ex2 failed");
  log_trace("EVP_EncryptInit_ex2 success");

  unsigned char crypted_text[1024] = {0};
  ret = EVP_Cipher(ctx, crypted_text, plaintext, plaintext_len);
  assert(ret && "EVP_Cipher failed");
  log_trace("EVP_Cipher success");

  EVP_CIPHER_CTX_free(ctx);
  log_trace("free old ctx");

  ctx = EVP_CIPHER_CTX_new();
  assert(ctx && "failed to new EVP_CIPHER_CTX");
  log_trace("EVP_CIPHER_CTX_new success");

  ret = EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL);
  assert(ret && "EVP_DecryptInit_ex2 failed");
  log_trace("EVP_DecryptInit_ex2 success");

  unsigned char decrypted_text[1024] = {0};
  ret = EVP_Cipher(ctx, decrypted_text, crypted_text, sizeof(crypted_text));
  assert(ret && "EVP_Cipher failed");
  log_trace("EVP_Cipher success");

  EVP_CIPHER_CTX_free(ctx);
  log_trace("free old ctx");

  if (strcmp((char*)crypted_text, (char*)decrypted_text) != 0) {
    log_error("cryption or decryption failed");
  }

  EVP_CIPHER_free(cipher);
  OSSL_PROVIDER_unload(prov_vcrypto);
  return 0;  
}
