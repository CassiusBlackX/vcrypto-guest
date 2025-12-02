#ifndef VCRYPTO_CIPHER_COMMON_H
#define VCRYPTO_CIPHER_COMMON_H

#include <openssl/params.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/modes.h>

# define MAXCHUNK    ((size_t)1 << 30)
# define MAXBITCHUNK ((size_t)1 << (sizeof(size_t) * 8 - 4))

# define GENERIC_BLOCK_SIZE 16
# define IV_STATE_UNINITIALISED 0  /* initial state is not initialized */
# define IV_STATE_BUFFERED      1  /* iv has been copied to the iv buffer */
# define IV_STATE_COPIED        2  /* iv has been copied from the iv buffer */
# define IV_STATE_FINISHED      3  /* the iv has been used - so don't reuse it */

/* Internal flags that can be queried */
# define PROV_CIPHER_FLAG_AEAD             0x0001
# define PROV_CIPHER_FLAG_CUSTOM_IV        0x0002
# define PROV_CIPHER_FLAG_CTS              0x0004
# define PROV_CIPHER_FLAG_TLS1_MULTIBLOCK  0x0008
# define PROV_CIPHER_FLAG_RAND_KEY         0x0010
/* Internal flags that are only used within the provider */
# define PROV_CIPHER_FLAG_VARIABLE_LENGTH  0x0100
# define PROV_CIPHER_FLAG_INVERSE_CIPHER   0x0200

typedef struct prov_cipher_ctx_st {
    /* place buffer at the beginning for memory alignment */
    /* The original value of the iv */
    unsigned char oiv[GENERIC_BLOCK_SIZE];
    /* Buffer of partial blocks processed via update calls */
    unsigned char buf[GENERIC_BLOCK_SIZE];
    unsigned char iv[GENERIC_BLOCK_SIZE];

    block128_f block;
    union {
        cbc128_f cbc;
        ctr128_f ctr;
        ecb128_f ecb;
    } stream;

    unsigned int mode;
    size_t keylen;           /* key size (in bytes) */
    size_t ivlen;
    size_t blocksize;
    size_t bufsz;            /* Number of bytes in buf */
    unsigned int cts_mode;   /* Use to set the type for CTS modes */
    unsigned int pad : 1;    /* Whether padding should be used or not */
    unsigned int enc : 1;    /* Set to 1 for encrypt, or 0 otherwise */
    unsigned int iv_set : 1; /* Set when the iv is copied to the iv/oiv buffers */
    unsigned int key_set : 1; /* Set when key is set on the context */
    unsigned int updated : 1; /* Set to 1 during update for one shot ciphers */
    unsigned int variable_keylength : 1;
    unsigned int inverse_cipher : 1; /* set to 1 to use inverse cipher */
    unsigned int use_bits : 1; /* Set to 0 for cfb1 to use bits instead of bytes */

    unsigned int tlsversion; /* If TLS padding is in use the TLS version number */
    unsigned char *tlsmac;   /* tls MAC extracted from the last record */
    int alloced;             /*
                              * Whether the tlsmac data has been allocated or
                              * points into the user buffer.
                              */
    size_t tlsmacsize;       /* Size of the TLS MAC */
    int removetlspad;        /* Whether TLS padding should be removed or not */
    size_t removetlsfixed;   /*
                              * Length of the fixed size data to remove when
                              * processing TLS data (equals mac size plus
                              * IV size if applicable)
                              */

    /*
     * num contains the number of bytes of |iv| which are valid for modes that
     * manage partial blocks themselves.
     */
    unsigned int num;
    const void *ks; /* Pointer to algorithm specific key data */
    OSSL_LIB_CTX *libctx;
} PROV_CIPHER_CTX;

void ossl_cipher_generic_reset_ctx(PROV_CIPHER_CTX *ctx);
OSSL_FUNC_cipher_encrypt_init_fn ossl_cipher_generic_einit;
OSSL_FUNC_cipher_decrypt_init_fn ossl_cipher_generic_dinit;
// OSSL_FUNC_cipher_update_fn ossl_cipher_generic_block_update;
// OSSL_FUNC_cipher_final_fn ossl_cipher_generic_block_final;
// OSSL_FUNC_cipher_update_fn ossl_cipher_generic_stream_update;
// OSSL_FUNC_cipher_final_fn ossl_cipher_generic_stream_final;
// OSSL_FUNC_cipher_cipher_fn ossl_cipher_generic_cipher;
OSSL_FUNC_cipher_get_ctx_params_fn ossl_cipher_generic_get_ctx_params;
OSSL_FUNC_cipher_set_ctx_params_fn ossl_cipher_generic_set_ctx_params;
OSSL_FUNC_cipher_gettable_params_fn     ossl_cipher_generic_gettable_params;
OSSL_FUNC_cipher_gettable_ctx_params_fn ossl_cipher_generic_gettable_ctx_params;
OSSL_FUNC_cipher_settable_ctx_params_fn ossl_cipher_generic_settable_ctx_params;

int ossl_cipher_generic_get_params(OSSL_PARAM params[], unsigned int md,
                                   uint64_t flags,
                                   size_t kbits, size_t blkbits, size_t ivbits);

// struct ossl_cipher_get_ctx_param_list_st {
//     OSSL_PARAM *keylen;         /* all ciphers */
//     OSSL_PARAM *ivlen;          /* all ciphers */
//     OSSL_PARAM *pad;            /* all ciphers */
//     OSSL_PARAM *num;            /* all ciphers */
//     OSSL_PARAM *iv;             /* all ciphers */
//     OSSL_PARAM *updiv;          /* all ciphers */
//     OSSL_PARAM *tlsmac;         /* generic cipher */
// };

// struct ossl_cipher_set_ctx_param_list_st {
//     OSSL_PARAM *pad;            /* all ciphers */
//     OSSL_PARAM *num;            /* all ciphers */
//     OSSL_PARAM *bits;           /* generic cipher */
//     OSSL_PARAM *tlsvers;        /* generic cipher */
//     OSSL_PARAM *tlsmacsize;     /* generic cipher */
//     OSSL_PARAM *keylen;         /* variable key length ciphers */
// };

// int ossl_cipher_common_get_ctx_params
//     (PROV_CIPHER_CTX *ctx, const struct ossl_cipher_get_ctx_param_list_st *p);
// int ossl_cipher_common_set_ctx_params
//     (PROV_CIPHER_CTX *ctx, const struct ossl_cipher_set_ctx_param_list_st *p);

int ossl_cipher_generic_initiv(PROV_CIPHER_CTX *ctx, const unsigned char *iv,
                               size_t ivlen);

// size_t ossl_cipher_fillblock(unsigned char *buf, size_t *buflen,
//                              size_t blocksize,
//                              const unsigned char **in, size_t *inlen);
// int ossl_cipher_trailingdata(unsigned char *buf, size_t *buflen,
//                              size_t blocksize,
//                              const unsigned char **in, size_t *inlen);

#endif // VCRYPTO_CIPHER_COMMON_H
