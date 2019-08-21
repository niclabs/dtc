#!/usr/bin/env sh
set -e
# Sign zone
./dhsm-signer sign -p ./dtc.so -f ./example.com -3 -z example.com -o example.com.signed && \

# Verify the zone already signed
./dhsm-signer verify -f ./example.com.signed -z example.com

# Reset HSM keys
./dhsm-signer reset-keys -p ./dtc.so
