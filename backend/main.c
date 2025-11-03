#include <log.h>

int main() {
  log_set_level(LOG_TRACE);
  log_trace("hello world!");
}
