#!/usr/bin/env sh
set -e
# Sign zone
./dhsm-signer -p11lib ./dtc.so -file ./example.com -nsec3 -zone example.com -output example.com.signed && \

# Verify the zone already signed
./dhsm-signer -file ./example.com.signed -zone example.com --verify_rrsig

# Reset HSM keys
./dhsm-signer -p11lib ./dtc.so -reset_keys
