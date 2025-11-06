#include <log.h>
#include <rte_cryptodev.h>
#include <stdint.h>
#include <stdio.h>

#include "cdev.h"
#include "khash.h"
#include "sess.h"
#include "util.h"

extern cdev_resource* cr;

KHASH_MAP_INIT_INT64(sess_map, sess_resource*)

struct HashMap {
  khash_t(sess_map)* map;
};

HashMap* hash_map_create() {
  HashMap* hm = malloc(sizeof(HashMap));
  if (!hm) {
    log_error("Failed to allocate for HashMap");
    return NULL;
  }
  hm->map = kh_init(sess_map);
  if (!hm->map) {
    log_error("failed to init map for Hashmap");
    free(hm);
    return NULL;
  }
  return hm;
}

void hash_map_destroy(HashMap* hm) {
  if (!hm) {
    log_debug("null pointer hm!");
    return;
  }
  
  for (khiter_t it = kh_begin(hm->map); it != kh_end(hm->map); it++) {
    if (kh_exist(hm->map, it)) {
      sess_resource* val = kh_val(hm->map, it);
      rte_cryptodev_sym_session_free(cr->cdev_id, val->sess);     
      free(val);
    }
  }

  kh_destroy(sess_map, hm->map);
}

bool hash_map_insert(HashMap* hm, uint64_t key, const sess_resource* value) {
  if (!hm || !value) {
    log_warn("null pointer either in hm or value");
    return false;
  }
  int ret;
  khiter_t it = kh_put(sess_map, hm->map, key, &ret);
  switch (ret) {
    case 0:
      log_warn("the key already exists, we will do nothing!");
      return false;
    case 1:
      // key did not exist in map
      kh_val(hm->map, it) = (sess_resource*)value;
      return true;
    case -1:
      log_error("failed to insert key = %zu into map", key);
      return false;
    default:
      return false;
  }
}

bool hash_map_get(const HashMap* hm, uint64_t key, const sess_resource** output_value) {
  if (!hm || !output_value) {
    log_warn("null pointer either in hm or output_value");
    return false;
  }
  khiter_t it = kh_get(sess_map, hm->map, key);
  if (it == kh_end(hm->map)) {
    log_warn("failed to get key = %zu in map", key);
    return false;
  } 
  *output_value = kh_value(hm->map, it);
  return true;
}

size_t hash_map_size(const HashMap* hm) {
  return hm ? kh_size(hm->map) : 0;
}
