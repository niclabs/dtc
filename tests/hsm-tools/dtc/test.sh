#!/usr/bin/env sh
set -e
# Sign zone with RSA
echo "Signing zone example.com with RSA keys..."
./hsm-tools sign pkcs11 -p ./dtc.so -f ./example.com -3 -z example.com -o example.com.signed -c -a rsa || {
  echo "Cannot sign properly"
  exit 1
}

echo "Signing successful!"

# Verify the zone already signed
echo "Verifying previous signature..."
./hsm-tools verify -f ./example.com.signed -z example.com || {
  echo "Cannot verify signature :("
  exit 1
}

echo "Verification successful!"

# Reset HSM keys
echo "Resetting keys..."
./hsm-tools reset-pkcs11-keys -p ./dtc.so -a rsa || {
  echo "Cannot reset keys :("
  exit 1
}

echo "Reset successful!"

# Sign zone with ECDSA
echo "Signing zone example.com with ECDSA keys..."
./hsm-tools sign pkcs11 -p ./dtc.so -f ./example.com -3 -z example.com -o example.com.signed -c -a ecdsa || {
  echo "Cannot sign properly"
  exit 1
}

echo "Signing successful!"

# Verify the zone already signed
echo "Verifying previous signature..."
./hsm-tools verify -f ./example.com.signed -z example.com || {
  echo "Cannot verify signature :("
  exit 1
}

echo "Verification successful!"

# Reset HSM keys
echo "Resetting keys..."
./hsm-tools reset-pkcs11-keys -p ./dtc.so -a ecdsa || {
  echo "Cannot reset keys :("
  exit 1
}

echo "Reset successful!"

echo "All tests passed. please kill this process with ^C."
