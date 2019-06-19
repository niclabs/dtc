FROM dtcnode-base:latest

RUN ./genconfig -n $DTC_NODE -s $DTC_SERVERS -k $DTC_PKS -o /etc/dtcnode/config.yaml && echo "starting $DTC_NODE_ID"

RUN apk del git pkgconfig gcc musl-dev

CMD ["/dtcnode/dtcnode"]
