#!/bin/bash
set -x


scp tests/tls/{ca.crt,redis.*} c@192.168.86.3:
docker -H ssh://c@192.168.86.3  stop redis
docker -H ssh://c@192.168.86.3  rm redis

# tls
# docker -H ssh://c@192.168.86.3 run --name redis -d --user 1000:1000 -v /home/c:/foo -p 6379:6379 redis --tls-port 6379 --port 0 --tls-cert-file /foo/redis.crt --tls-key-file /foo/redis.key --tls-ca-cert-file /foo/ca.crt


# not tls
docker -H ssh://c@192.168.86.3 run --name redis -d --user 1000:1000 -v /home/c:/foo -p 6379:6379 redis
sleep 4
docker -H ssh://c@192.168.86.3 logs redis
