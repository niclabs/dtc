FROM golang:alpine

MAINTAINER Eduardo Riveros<eduardo@niclabs.cl>

WORKDIR /
RUN apk add zeromq-dev czmq-dev git pkgconfig gcc musl-dev
RUN git clone https://github.com/niclabs/dtcnode --branch master --single-branch

WORKDIR /dtcnode
RUN go clean --modcache
RUN go mod download
RUN go build

RUN mkdir /etc/dtcnode

RUN apk del git pkgconfig gcc musl-dev

CMD /dtcnode/dtcnode
