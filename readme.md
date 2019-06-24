# PKCS11-Compatible Distributed Threshold Criptography Library Signer

A Golang rework of [our C++ Library](https://github.com/niclabs/tchsm-libdtc) in Golang, but using a PKCS#11 interface.

This library requires the use of two or more instances of [dtcnode](https://github.com/niclabs/dtcnode).


# How to compile

To compile the library, just clone this repository and execute build.sh. This will create a file named `dtc.so`, which you can use in any PKCS#11-compatible software.

For this signer to work, you need to configure it properly. You can use the config.yml as an example.
