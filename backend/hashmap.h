#ifndef VCRYPTO_GUEST_UTIL_H
#define VCRYPTO_GUEST_UTIL_H

#include <stdbool.h>
#include <stdint.h>

#include "sess.h"

typedef struct HashMap HashMap;
// initialize a hash map
// return NULL if init failed
bool hash_map_create();
// destroy a hashmap
// but the caller should make sure all the resources in it freed before calling this
void hash_map_destroy();
// insert a kv into hashmap
// only return true when there was not such a key in map, and inserted success
// NOTE: will not update `val` if there was already the same key and will return false
// also return false when insert key failed
bool hash_map_insert(uint64_t key, const sess_resource* value);
// return NULL if not found kv pair
// else return pointer
sess_resource* hash_map_get(uint64_t key);
// will ref_count-- if kv pair found
// if ref_count == 0, will release resource, and return true
// if no resource is release, will return false
bool hash_map_retrieve(uint64_t key);
// return the number of kvs in hash map
size_t hash_map_size();

extern HashMap* g_sess_map;
#endif // VCRYPTO_GUEST_UTIL_H
