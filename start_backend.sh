#!/bin/bash

./build/backend/vcrypto_engine_backend \
-l 3-4 \
--file-prefix=vcrypto \
--proc-type=primary 

# uncomment the following line if running on host 
# --vdev crypto_openssl
