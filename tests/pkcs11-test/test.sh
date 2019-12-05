#!/usr/bin/env bash
set -e
cd "$(dirname $0)" || exit
../../build.sh ../../
go run github.com/niclabs/dtcconfig rsa \
            -n 0.0.0.0:8871,0.0.0.0:8873,0.0.0.0:8875,0.0.0.0:8877,0.0.0.0:8879 \
            -t 3 \
            -H "$(ip addr | grep 'global docker0' | awk '{print $2}' | sed sx/16xxg)" \
            -c "config.yaml" \
            -k "config/" \
            -d "db.sqlite3"
docker-compose build
docker-compose up -d
sleep 30
