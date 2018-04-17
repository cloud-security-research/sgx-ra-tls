#!/bin/bash

# Build project from scratch in a Docker container.

set -e
set -x

REPO_DIR=$(readlink -f .)
TEMP_DIR=$(mktemp -d /var/tmp/ratls-XXX)

POSITIONAL=()
while [[ $# -gt 0 ]]
do
    key="$1"

    case $key in
        -i|--image)
            IMAGE="$2"
            shift # past argument
            shift # past value
            ;;
        -k|--keep)
            CMD=" ; bash"
            shift # past argument
            ;;
        *)    # unknown option
            POSITIONAL+=("$1") # save it in an array for later
            shift # past argument
            ;;
    esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

pushd $TEMP_DIR
git clone $REPO_DIR
cd $(basename $REPO_DIR)

# --privileged=true is required for SGX-LKL only. The build process
# for SGX-LKL wants to mount things, uses iptables, etc.

docker run --device=/dev/isgx --device=/dev/gsgx \
       --privileged=true \
       -v /var/run/aesmd:/var/run/aesmd \
       -v$(pwd):/project \
       -it $IMAGE bash -c "cd /project $CMD"
popd
