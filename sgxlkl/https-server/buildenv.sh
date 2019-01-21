#!/bin/sh

set -ex

PATH=/usr/sbin:/sbin:/usr/bin:/bin

cd /home
echo "http://dl-cdn.alpinelinux.org/alpine/v3.6/community" >> /etc/apk/repositories
apk update
apk add openssl
apk add openssl-dev
apk add make
apk add build-base
apk update && apk add ca-certificates wget && update-ca-certificates
apk add openssl
wget https://www.python.org/ftp/python/2.7.15/Python-2.7.15.tgz 
tar -xvzf Python-2.7.15.tgz
cd Python-2.7.15/ && ./configure && make && make install && mv python /usr/bin
