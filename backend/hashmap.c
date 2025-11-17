#include <log.h>
#include <rte_cryptodev.h>
#include <stdint.h>
#include <stdio.h>

#include "khash.h"
#include "sess.h"
#include "hashmap.h"

KHASH_MAP_INIT_INT64(sess_map, sess_resource*)

struct HashMap {
  khash_t(sess_map)* map;
};

struct HashMap* g_sess_map;

bool hash_map_create() {
  HashMap* hm = malloc(sizeof(HashMap));
  if (!hm) {
    log_error("Failed to allocate for HashMap");
    return false;
  }
  hm->map = kh_init(sess_map);
  if (!hm->map) {
    log_error("failed to init map for Hashmap");
    free(hm);
    return false;
  }
  g_sess_map = hm;
  return true;
}

void hash_map_destroy() {
  if (!g_sess_map) {
    log_debug("null pointer of g_sess_map");
    return;
  }
  
  kh_destroy(sess_map, g_sess_map->map);
}

bool hash_map_insert(uint64_t key, const sess_resource* value) {
  if (!g_sess_map || !value) {
    log_warn("null pointer either in g_sess_map or value");
    return false;
  }
  int ret;
  khiter_t it = kh_put(sess_map, g_sess_map->map, key, &ret);
  switch (ret) {
    case 0:
      log_warn("the key already exists, we will do nothing!");
      return false;
    case 1:
      // key did not exist in map
      kh_val(g_sess_map->map, it) = (sess_resource*)value;
      return true;
    case -1:
      log_error("failed to insert key = %zu into map", key);
      return false;
    default:
      return false;
  }
}

sess_resource* hash_map_get(uint64_t key) {
  if (!g_sess_map) {
    log_warn("null pointer in hm");
    return NULL;
  }
  khiter_t it = kh_get(sess_map, g_sess_map->map, key);
  if (it == kh_end(g_sess_map->map)) {
    log_trace("failed to get key = %zu in map", key);
    return NULL;
  } 
  return kh_value(g_sess_map->map, it);
}

bool hash_map_retrieve(uint64_t key) {
  if (!g_sess_map) {
    log_warn("null pointer g_sess_map");
    return false;
  }
  khiter_t it = kh_get(sess_map, g_sess_map->map, key);
  if (it == kh_end(g_sess_map->map)) {
    log_trace("failed to get key = %zu in map", key);
    return false;
  }

  sess_resource* sr = kh_val(g_sess_map->map, it);
  sr->ref_count--;

  if (sr->ref_count == 0) {
    log_trace("key: %d ref_count reached 0, destroying it", key);
    sess_resource_destroy(sr);
    kh_del(sess_map, g_sess_map->map, it);
  } else {
    log_trace("key: %d ref_count decremented to %d", key, sr->ref_count);
  }
  return true;
}

size_t hash_map_size() {
  return g_sess_map ? kh_size(g_sess_map->map) : 0;
}
