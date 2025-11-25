#!/bin/bash

./build/backend/vcrypto_engine_backend \
-l 6-7 \
--file-prefix=vcrypto \
--proc-type=primary \
--vdev crypto_openssl
