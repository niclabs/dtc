# PKCS11-Compatible Distributed Threshold Cryptography Library Signer

A Golang rework of [our C++ Library](https://github.com/niclabs/tchsm-libdtc) in Golang, but using a PKCS#11 interface.

This library requires the use of two or more instances of [dtcnode](https://github.com/niclabs/dtcnode).

# How to build

First, it's necessary to download all the requirements of the Go project. The following libraries should be installed in the systems which are going to use the library:

* libzmq3-dev v4 or greater (for zmq communication with the nodes)
* libczmq-dev (for zmq communication with the nodes)
* gcc
* sqlite3 (used in HSM data storage)
* Go (1.13.4 or higher)

for building the project as a library, you should execute the following command. It will produce a file named `dtc.so`, which can be used as a PKCS#11 driver.

`./build.sh`


On Ubuntu 18.04 LTS, the commands to run to build are the following:

```bash
# Install requirements
sudo apt install libzmq3-dev libczmq-dev build-essential sqlite3 pkg-config

# Download and install Go 1.13.4 for Linux AMD 64 bit.
wget https://dl.google.com/go/go1.13.4.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.13.4.linux-amd64.tar.gz

# ADD /usr/local/go to PATH
export PATH=$PATH:/usr/local/go

# Clone and compile repository
git clone https://github.com/niclabs/dtc
cd dtc
./build.sh
```

# How to configure

The configuration file is named `config.yaml` and it can be in the current working directory or in `/etc/dtc/` folder. the structure is similar to the following (**PLEASE DO NOT USE THIS PUBLIC/PRIVATE KEY PAIR FOR THE SERVER**):

```yaml
dtc:
  general:
    logfile: /tmp/dtc.log
    dtc:
      messagingType: zmq
      nodesNumber: 5
      threshold: 3

    criptoki:
      manufacturerId: "NICLabs"
      model: "TCHSM"
      description: "Implementación de PKCS11"
      serialnumber: "1"
      minPinLen: 3
      maxPinLen: 10
      maxSessionCount: 5
      databaseType: sqlite3
      slots:
        - label: TCBHSM
          PIN: 1234

  sqlite3:
    path: db.sqlite3

  zmq:
    timeout: 10
    publicKey: "{0j3IXL0Jw:)K$b1@(1=<8z/joPM.c+EXVBMS>7$"
    privateKey: "F(/uq@m$}KW>)X=0yKRh}lg!N![Efl<@3<Bbelp3"
    nodes:
      - host: 127.0.0.1
        publicKey: '@?Bpu79j8JG1$BGhUHx@bl?jaLB6Tg].V3XjCHiy'
        port: 9871
      - host: 127.0.0.1
        publicKey:  '{ru14[eTvFFr^o}wL}#J[z4{ci7+P1gHv<on#[{z'
        port: 9873
      - host: 127.0.0.1
        publicKey: '*@tRX8)p=ty]7oZbJZ/Stm>=3Qd{P$[IG?ba>q3f'
        port: 9875
      - host: 127.0.0.1
        publicKey: pZd<H6rhZ:3Eky<5A=Gvq]BLHL^a-@H+)tP?L-+7
        port: 9877
      - host: 127.0.0.1
        publicKey: WEz4<>x8dul]2ELx$r60C-gTVf0O8=M>Z7ZV%ihW
        port: 9879
  ```

It has a mandatory section, called `general`, where we currently define three variables:
* `logfile` is the absolute path where the log is going to be saved. If empty or undefined, the log will be printed on the stderr of the program which is using the library.
* `dtc` represents the specific configuration used by the server. It defines a `messagingType` (Currently, only ZMQ), a `nodesNumber` value (the total number of nodes that are going to participate in the protocol) and a `threshold` number (the minimum number of nodes that need to sign a document to declare it as signed correctly.
* `criptoki` defines the following Criptoki/PKCS#11 specific variables:
 - `manufacturerId` is the ID of the manufacturer of the HSM.
 - `model` is the model of the HSM.
 - `description` is a brief description of the HSM.
 - `serialNumber` is the serial number of the HSM.
 - `minPinLen` is the minimum length for the PINs.
 - `maxPinLen` is the maximum length for the PINs.
 - `maxSessionCount` is the maximum number of simultaneous sessions.
 - `databaseType` is the type of the storage for the HSM. Currently the only value available is `sqlite3`.
 - `slots` defines the slots available on the HSM. Each slot has a `label` field, representing the slot name, and a `PIN` field, used in token creation only. the HSM creates by default the slots defined here.
 
 
Also, there are two extra configurations outside `general` option:

* **Network Configurations**: They define the options for the network driver. Currently, `zmq` is the only available, but the implementation allows to extend it to other messaging systems. `zmq` defines the following options:
 * `timeout` represents the maximum time a node should be waited to declare it as non responsive.
 * `publicKey` represents a Base85 public key used by _ZMQ CURVE Auth_ mode. The nodes should communicate in this mode to send and receive encripted messages.
 * `host` represents the local IP where the ZMQ server will bind.
 * `port` represents the local TCP port where the ZMQ server will bind.
 * `nodes` is a list of dictionaries with node information. This list must be of the same size as the `nodesNumber` variable in `general.dtc`. Each node is represented by `host`, `port` and `publicKey` parameters (IP/Port/Public Key of the node).
* **Storage Configurations**: They define the options for the storage driver. Currently, `sqlite3` is the only available, but the implementation allows to extend it to other storage systems. `sqlite3` defines the following options:
 * `path` is the path to the sqlite3 database. 
 
 
If you need to generate a public/private Base85 key pair for ZMQ Curve Authentication, we recommend to use the `gencurve`utility in [dtcnode repository](https://github.com/niclabs/dtcnode).

# How to test

This project includes two test types:
 
 ## dhsm-signer
 This test is in `/tests/dhsm-signer/`, and includes a _Docker Compose_ configuration with five DTC ZMQ nodes, used for signing a DNSSEC zone with [dhsm-signer](https://github.com/niclabs/dhsm-signer). 

To run the integration test, first you need to create a file named `dtcnode.env` with the variables `DTC_SERVER` (the IP:Port of the machine in Docker configuration, `DTC_PK` (the public key the server will use)  and `DTC_NODE` (IP:Port used by the node) on the folder `tests/dhsm-signer`. Then, you should execute 

`./tests/dhsm-signer/test.sh`.


For more information about the ports bound in the docker configuration, it's recommended to check the `docker-compose.yml` file.

## pkcs11-test

 This test is located in `tests/pkcs11-test` and is used to check that the PKCS11-compatible library uses properly its API.
 
 The tests are borrowed from the [Go PKCS11 Library](https://github.com/miekg/pkcs11), modifying some paths to use the dtc.so library.
 
 To execute this tests, first you need to compile the shared object executing `./build.sh` on the project root file. 
 
 Then, you need to start some dtcnodes. We include a dockerfile with 5 dtcnodes and some prefilled key pairs. They are bound to the `tests/pkcs11-test/config.yml` config file, that will be used when executing the PKCS11 go tests. To start the nodes, you must run `./tests/pkcs11-test/test.sh`. This will start the nodes.
 
 Finally, you need to execute the tests. This can be accomplished executing `go test dtc/tests/pkcs1-test`.

