#!/usr/bin/env bash
docker build -t dtcnode-base dtcnode-base/
docker-compose build node{1..5}
docker-compose up -d
