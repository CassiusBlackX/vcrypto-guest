#include <dlfcn.h>
#include <stdio.h>

#ifndef PROJECT_BUILD_DIR
#define PROJECT_BUILD_DIR ".."
#endif

int main() {
  char dl_path[256];
  snprintf(dl_path, sizeof(dl_path), "%s/frontend/vcrypto.so", PROJECT_BUILD_DIR);
  printf("dl_path: %s\n", dl_path);
  void *h = dlopen("/home/cassius/vcrypto_guest/build/frontend/vcrypto.so", RTLD_NOW | RTLD_GLOBAL);
  if (!h) {
    printf("dlopen failed :%s\n", dlerror());
    return 1;
  }
  void *sym = dlsym(h, "OSSL_provider_init");
  if (!sym) {
    printf("dlsym failed: %s\n", dlerror());
    dlclose(h);
    return 1;
  }
  printf("ok, dlopen and dlsym\n");
  dlclose(h);
  return 0;
}
