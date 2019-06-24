FROM golang:alpine

MAINTAINER Eduardo Riveros<eduardo@niclabs.cl>

ENV DTC_NODE 0.0.0.0:2030
ENV DTC_SERVERS localhost:2030
ENV DTC_PKS changeme

WORKDIR /
RUN apk add zeromq-dev czmq-dev git pkgconfig gcc musl-dev
RUN git clone https://github.com/niclabs/dtcnode -b final #fdkgjkh

WORKDIR /dtcnode
RUN go mod tidy
RUN go build

WORKDIR /dtcnode/genconfig
RUN go mod tidy
RUN go build

RUN mkdir /etc/dtcnode

RUN apk del git pkgconfig gcc musl-dev

CMD /dtcnode/genconfig/genconfig -n $DTC_NODE -s $DTC_SERVERS -k $DTC_PKS -o /etc/dtcnode/config.yaml && /dtcnode/dtcnode
