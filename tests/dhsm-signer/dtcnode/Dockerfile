FROM golang:alpine

MAINTAINER Eduardo Riveros<eduardo@niclabs.cl>

WORKDIR /
RUN apk add zeromq-dev czmq-dev git pkgconfig gcc musl-dev
RUN git clone https://github.com/niclabs/dtcnode --branch v1.1.0 --single-branch

WORKDIR /dtcnode
RUN go mod tidy
RUN go build

RUN mkdir /etc/dtcnode

RUN apk del git pkgconfig gcc musl-dev

# Sleep because we need to wait the network to be initialized
CMD sleep 5 && /dtcnode/dtcnode
