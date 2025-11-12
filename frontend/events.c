#include <errno.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <openssl/async.h>

#include <log.h>

#include "events.h"

static void vcrypto_fd_cleanup(ASYNC_WAIT_CTX* ctx, const void* key,
                               OSSL_ASYNC_FD readfd, void* custom) {
  log_debug("vcrypto_fd_cleanup called");
  if (close(readfd) != 0) {
    log_error("failed to close fd: %d - error: %d", readfd, errno);
  } else {
    log_trace("closed fd async fd: %d, to close be async fd: %d", readfd, *((int*)(custom)));
    
  }
}
