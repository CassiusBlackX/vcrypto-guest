#ifndef VCRYPTO_GUEST_BE_SESS
#define VCRYPTO_GUEST_BE_SESS

#include <openssl/async.h>
#include <rte_cryptodev.h>
#include <rte_ring.h>

typedef struct {
  struct rte_crypto_sym_session *sess;
  size_t ret_count;
} sess_resource;

// NOTE: alg_elems is used by backend to create sess, backend does not have to maintain alg_elems
// it is `VM-Exit` during virtio-create-sess that is inefficient, transferring ~150 bytes between fe and be is acceptable

sess_resource* get_sess_resource(uint8_t *alg_elems, uint8_t cdev_id);
void put_sess_resource(uint64_t md5_hash);

#endif // VCRYPTO_GUEST_BE_SESS
