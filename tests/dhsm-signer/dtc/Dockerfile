FROM golang:buster

MAINTAINER Eduardo Riveros<eduardo@niclabs.cl>

WORKDIR /
RUN apt update
RUN apt -y install libzmq3-dev libczmq-dev build-essential sqlite3

RUN git clone https://github.com/niclabs/dtc --branch master #

WORKDIR /dtc
ENV GO111MODULE on
RUN go mod download
RUN ./build.sh

WORKDIR /
RUN git clone https://github.com/niclabs/dhsm-signer --branch v1.0

WORKDIR /dhsm-signer
RUN go mod tidy
RUN go build

RUN mv /dtc/dtc.so /dhsm-signer/dtc.so #s

# copy example zone and test with this shellscript
COPY test.sh test.sh
COPY example.com example.com

# Sleep because we need to wait the network to be initialized
CMD sleep 5 && ./test.sh
