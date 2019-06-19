# PKCS11-Compatible Distributed Threshold Criptography Library

A Golang rework of [our C++ Library](https://github.com/niclabs/tchsm-libdtc) in Golang, but using a PKCS#11 interface.

This library requires the use of two or more instances of [dtcnode](https://github.com/niclabs/dtcnode).


# How to build

First, it's necessary to download all the requirements of the go project. The following libraries should be installed in the systems which are going to use the library:

* libzmq-dev v4 or greater (for zmq communication with the nodes)
* czmq (for zmq communication with the nodes)
* gcc (`build-essentials` should suffice in Ubuntu)


And the following command installs the required golang libraries:

`go mod tidy`

for building the project as a library, you should execute the following command. It will produce a file named `dtc.so`, which can be used as a PKCS#11 driver.

`./build.sh`

# How to test

This project includes a _Docker Compose_ configuration with five DTC ZMQ nodes. To run the integration tests, first you need to create a file named `dtcnode.env` with the variables `DTC_SERVERS` (a comma separated list of servers and ports related to the node), `DTC_PKS` (a comma separated list of public keys for each node declared in `DTC_SERVERS`) and `DTC_NODE` (an IP and port used by the node) on the folder integration_test. Then, you should execute 

`./integration_test/test.sh`.

If you only want to run the dockerized nodes, you need to execute 

`/integration_test/start_nodes.sh`


For more information about the ports bound in the docker configuration, it's reccomended to check the `docker-compose.yml` file.
