FROM golang:alpine

MAINTAINER Eduardo Riveros<eduardo@niclabs.cl>

WORKDIR /
RUN apk add zeromq-dev czmq-dev git pkgconfig gcc musl-dev
RUN git clone https://github.com/niclabs/dtc

WORKDIR /dtc
RUN go mod tidy
RUN ./build.sh

WORKDIR /
RUN git clone https://github.com/niclabs/dhsm-signer --branch v0.8

WORKDIR /dhsm-signer
RUN go mod tidy
RUN go build

RUN apk del git gcc musl-dev

COPY test.sh test.sh
COPY example.com example.com

CMD ./test.sh
