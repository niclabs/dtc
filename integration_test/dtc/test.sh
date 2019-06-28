#!/usr/bin/env bash
./dhsm-signer -file ./example.com -p11lib "/dtc/dtc.so" -nsec3 -zone example.com -output ./example.com.signed

./dhsm-signer -file ./example.com -zone example.com --verify_rrsig

./dhsm-signer -reset_keys -p11lib "/dtc/dtc.so"
