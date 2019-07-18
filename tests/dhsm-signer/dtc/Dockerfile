FROM golang:stretch

MAINTAINER Eduardo Riveros<eduardo@niclabs.cl>

WORKDIR /
RUN apt update
RUN apt -y install libzmq3-dev libczmq-dev build-essential sqlite3
RUN git clone https://github.com/niclabs/dtc --branch v1.1.1

WORKDIR /dtc
RUN go mod tidy
RUN ./build.sh

WORKDIR /
RUN git clone https://github.com/niclabs/dhsm-signer --branch v0.8

WORKDIR /dhsm-signer
RUN go mod tidy
RUN go build

RUN mv /dtc/dtc.so /dhsm-signer/dtc.so

# copy example zone and test with this shellscript
COPY test.sh test.sh
COPY example.com example.com

# Sleep because we need to wait the network to be initialized
CMD sleep 5 && ./test.sh
