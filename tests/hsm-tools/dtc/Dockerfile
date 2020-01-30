FROM golang:1.13.4-buster

MAINTAINER Eduardo Riveros<eduardo@niclabs.cl>

WORKDIR /
RUN apt update
RUN apt -y install libzmq3-dev libczmq-dev build-essential sqlite3

COPY ./dtc /dtc/

WORKDIR /dtc
ENV GO111MODULE on
RUN go mod download
RUN ./build.sh

WORKDIR /
RUN git clone https://github.com/niclabs/hsm-tools

WORKDIR /hsm-tools
RUN go mod tidy
RUN go build

RUN mv /dtc/dtc.so /hsm-tools/dtc.so

# copy example zone and test with this shellscript.
COPY ./dtc/tests/hsm-tools/dtc/test.sh test.sh
COPY ./dtc/tests/hsm-tools/dtc/example.com example.com

# Sleep because we need to wait the network to be initialized
CMD sleep 5 && ./test.sh
