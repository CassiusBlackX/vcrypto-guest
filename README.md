# vcrypto
## compile
the project is configured using `cmake`, and depends on `dpdk`.

### env set
supposing that `dpdk` is installed. but `cmake` uses `pkg-config` to look up for dpdk,
therefore the `PKG_CONFIG_PATH` should be configured.

for example, on kunpeng servers with openeuler, dpdk is usually installed at 
'/usr/local/lib64/pkgconfig', in which you should be able to find "libdpdk.pc" file. 

run the following command before using `cmake` cmd.
```sh
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib64/pkgconfig
```

### project configure and compile
at project root dir,
```sh
cmake -B build -S . -G Ninja -DRELEASE_MODE=ON -DCMAKE_BUILD_TYPE=RELEASE
```
if any warning messages are confronted, you should check your env.

by default, openssl will lookup for providers under '/usr/lib64/ossl-modules'
(if openssl is installed within distribution).
if this directory does not exist, you should look for other places for "ossl-modules",
and modify the `OPENSSL_ENGINE_DIR` variable in 'frontend/CMakeLists.txt' to your path.

then you can compile and install vcrypto.
```sh
cmake --build build
# since install path is at /usr/lib64, a sudo privilige is needed
sudo cmake --install build 
```

you can find 'vcrypto.so' under your `OPENSSL_ENGINE_DIR` path.

## run test
this is a backend and frontend project, in which backend must be started first.

### start backend
in a vm, backend can be started using the `start_backend.sh` script in the project root dir.
```sh
./start_backend.sh
```

### start frontend
using the following cmd to run a simplest openssl speed test
```sh
openssl speed -elapsed -provider vcrypto aes-256-cbc
```

to configure the `bytes` variable at benchmark, using the following cmd
```sh
openssl speed -elapsed -provider vcrypto -bytes ${my_test_bytes} aes-256-cbc
```
where `my_test_bytes` is suggested to be the power of 2.

