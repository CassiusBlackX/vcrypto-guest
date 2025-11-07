#ifndef VCRYPTO_GUEST_UTIL_H
#define VCRYPTO_GUEST_UTIL_H

#include "sess.h"
#include <stdbool.h>
#include <stdint.h>

#include <khash.h>
#include <stdlib.h>

void vcrypto_hex_dump(char* description, char *buf, int len);

typedef struct HashMap HashMap;
// initialize a hash map
// return NULL if init failed
HashMap* hash_map_create();
// destroy a hashmap, and all its containing resources
void hash_map_destroy(HashMap* hm);
// insert a kv into hashmap
// only return true when there was not such a key in map, and inserted success
// NOTE: will not update `val` if there was already the same key and will return false
// also return false when insert key failed
bool hash_map_insert(HashMap* hm, uint64_t key, const sess_resource* value);
// return true if found kv, and will make `output_value` pointing to the value from the hash_map
bool hash_map_get(const HashMap* hm, uint64_t key, const sess_resource** output_value);
// return the number of kvs in hash map
size_t hash_map_size(const HashMap* hm);

#endif // VCRYPTO_GUEST_UTIL_H
