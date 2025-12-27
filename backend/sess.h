#ifndef VCRYPTO_GUEST_BE_SESS
#define VCRYPTO_GUEST_BE_SESS

#include <openssl/async.h>
#include <rte_cryptodev.h>
#include <rte_ring.h>

#include "../frontend/cipher_common.h"

// TODO: the struct is not needed!
// we can use rte_cryptodev_session_priate_data, filling the refcout inside
typedef struct {
  struct rte_crypto_sym_session *sess;
  size_t ref_count;
} sess_resource;

// descturctor of type `sess_resource`
void sess_resource_destroy(sess_resource* sr);

// used by protocol
sess_resource* get_sess_resource(const PROV_CIPHER_CTX* cipher_auth);
void release_sess_resource(uint64_t md5_hash);

#endif // VCRYPTO_GUEST_BE_SESS
