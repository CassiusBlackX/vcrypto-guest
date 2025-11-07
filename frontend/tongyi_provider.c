// provider.c
#include <openssl/core_dispatch.h>
#include <openssl/core_object.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <string.h>

/* 上下文结构 */
typedef struct {
    unsigned char key[32];   // max AES-256
    unsigned char iv[16];
    int keylen;              // 16 or 32
    int encrypt;             // 1=encrypt, 0=decrypt
} UDS_CIPHER_CTX;

/* ---------- Cipher Ops ---------- */

static void *cipher_newctx(void *provctx) {
    return OPENSSL_zalloc(sizeof(UDS_CIPHER_CTX));
}

static void cipher_freectx(void *vctx) {
    OPENSSL_clear_free(vctx, sizeof(UDS_CIPHER_CTX));
}

static int cipher_encrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                              const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[]) {
    UDS_CIPHER_CTX *ctx = (UDS_CIPHER_CTX *)vctx;
    if (keylen != 16 && keylen != 32) return 0;
    memcpy(ctx->key, key, keylen);
    ctx->keylen = (int)keylen;
    if (iv) memcpy(ctx->iv, iv, 16);
    ctx->encrypt = 1;
    return 1;
}

static int cipher_decrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                              const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[]) {
    UDS_CIPHER_CTX *ctx = (UDS_CIPHER_CTX *)vctx;
    if (keylen != 16 && keylen != 32) return 0;
    memcpy(ctx->key, key, keylen);
    ctx->keylen = (int)keylen;
    if (iv) memcpy(ctx->iv, iv, 16);
    ctx->encrypt = 0;
    return 1;
}

static int cipher_update(void *vctx, unsigned char *out, size_t *outl,
                         const unsigned char *in, size_t inl) {
    // 直接拷贝（CBC 需要 padding，但 OpenSSL 会在 final 处理）
    memcpy(out, in, inl);
    *outl = inl;
    return 1;
}

static int cipher_final(void *vctx, unsigned char *out, size_t *outl) {
    UDS_CIPHER_CTX *ctx = (UDS_CIPHER_CTX *)vctx;
    size_t total_len = /* 你需要记录 update 的总长度 */;
    // 实际项目中需缓存所有 input，这里简化：假设所有数据已在 out 中
    // 👇 真正转发到 UDS
    if (!uds_do_aes_cbc(ctx->encrypt, ctx->key, ctx->keylen, ctx->iv, out, total_len, out)) {
        return 0;
    }
    *outl = total_len;
    return 1;
}

static const OSSL_PARAM cipher_known_gettable_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *cipher_gettable_params(void *provctx) {
    return cipher_known_gettable_params;
}

static int cipher_get_params(OSSL_PARAM params[]) {
    OSSL_PARAM *p;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE)) != NULL)
        OSSL_PARAM_set_size_t(p, 16); // AES block size
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE)) != NULL)
        OSSL_PARAM_set_uint(p, EVP_CIPH_CBC_MODE);
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD)) != NULL)
        OSSL_PARAM_set_int(p, 0);
    return 1;
}

/* Cipher dispatch table for AES-128-CBC */
static const OSSL_DISPATCH aes128_cbc_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))cipher_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))cipher_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))cipher_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))cipher_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))cipher_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))cipher_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))cipher_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))cipher_gettable_params },
    { 0, NULL }
};

/* 同样定义 aes256_cbc_functions... */

/* ---------- Provider Interface ---------- */

static const OSSL_ALGORITHM supported_ciphers[] = {
    { "AES-128-CBC:1.2.840.113549.3.7", "provider=uds,fips=no", aes128_cbc_functions },
    { "AES-256-CBC:2.16.840.1.101.3.4.1.42", "provider=uds,fips=no", aes256_cbc_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *query_operation(void *provctx, int operation_id, const int *no_cache) {
    switch (operation_id) {
        case OSSL_OP_CIPHER:
            return supported_ciphers;
    }
    return NULL;
}

/* 必须导出的初始化函数 */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx) {
    static const OSSL_DISPATCH provider_table[] = {
        { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))query_operation },
        { 0, NULL }
    };
    *out = provider_table;
    *provctx = NULL; // 可用于保存 UDS 连接等
    return 1;
}
