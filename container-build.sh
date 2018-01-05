#!/bin/bash

# Build project from scratch in a Docker container.

set -e
set -x

REPO_DIR=$(readlink -f .)
TEMP_DIR=$(mktemp -d /var/tmp/ratls-XXX)

CMD=""
if [ "$1" = "keep" ] ; then
   CMD=" ; bash"
fi

pushd $TEMP_DIR
git clone $REPO_DIR
cd $(basename $REPO_DIR)
docker run --device=/dev/isgx --device=/dev/gsgx -v /var/run/aesmd:/var/run/aesmd \
       -v$(pwd):/project \
       -e https_proxy='https://proxy.jf.intel.com:912' \
       -e http_proxy='http://proxy.jf.intel.com:911' \
       -it ubuntu:16.04 bash -c "cd /project ; bash ./build.sh container $CMD"
popd
