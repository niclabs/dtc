#!/usr/bin/env bash
set -e
cd "$(dirname $0)" || exit
go run github.com/niclabs/dtcconfig rsa \
  -n dtcnode1:2030,dtcnode2:2030,dtcnode3:2030,dtcnode4:2030,dtcnode5:2030 \
  -t 3 \
  -H "dtcclient" \
  -c "dtc/config/config.yaml" \
  -k "dtcnode/config/"
docker-compose build
docker-compose up
