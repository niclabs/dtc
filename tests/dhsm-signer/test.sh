#!/usr/bin/env bash
set -e
cd "$(dirname $0)" || exit
go run github.com/niclabs/dtcconfig rsa \
            -n 0.0.0.0:2030,0.0.0.0:2030,0.0.0.0:2030,0.0.0.0:2030,0.0.0.0:2030 \
            -t 3 \
            -H "dtcclient" \
            -c "dtc/config/config.yaml" \
            -k "dtcnode/config/"
docker-compose build
docker-compose up
