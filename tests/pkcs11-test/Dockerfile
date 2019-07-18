FROM golang:alpine

MAINTAINER Eduardo Riveros<eduardo@niclabs.cl>

WORKDIR /
RUN apk add zeromq-dev czmq-dev git pkgconfig gcc musl-dev
RUN git clone https://github.com/niclabs/dtcnode --branch v1.1.0

WORKDIR /dtcnode
RUN go mod tidy
RUN go build

WORKDIR /dtcnode/genconfig
RUN go mod tidy
RUN go build

RUN mkdir /etc/dtcnode

RUN apk del git pkgconfig gcc musl-dev

CMD /dtcnode/dtcnode
