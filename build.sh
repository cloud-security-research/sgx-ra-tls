#!/bin/bash

set -x

function usage() {
    echo "./build.sh sgxsdk|graphene|scone|sgxlkl"
}

# You need the SGX SDK and PSW installed.

if [[ $# -gt 1 || $# -eq 0 ]]; then
    echo "wrong number of arguments"
    usage
    exit 1
fi

[[ $# -eq 1 ]] && VARIANT=$1

if [[ ! ( $VARIANT == "scone" ||
                $VARIANT == "graphene" ||
                $VARIANT == "sgxsdk" ||
                $VARIANT == "sgxlkl" ) ]] ; then
    echo "unknown variant; must be one of sgxsdk, graphene, scone or sgxlkl."
    usage
    exit 1
fi

# Choose compiler to build deps.
if [[ ( $VARIANT == "graphene" || $VARIANT == "sgxsdk" || $VARIANT == "sgxlkl" ) ]] ; then
    export CC=gcc
elif [[ $VARIANT == "scone" ]] ; then
    export CC=/usr/local/bin/scone-gcc
fi

make ra_tls_options.c

mkdir -p deps
make -j`nproc` deps
pushd deps

# The OpenSSL, wolfSSL, mbedtls libraries are necessary for the non-SGX
# clients. We do not use their package versions since we need them to
# be compiled with specific flags.

# if [[ ! -d mbedtls ]] ; then
#     git clone https://github.com/ARMmbed/mbedtls.git
#     pushd mbedtls
#     git checkout mbedtls-2.5.1
#     # Add  -DCMAKE_BUILD_TYPE=Debug for Debug
#     patch -p1 < ../../mbedtls-enlarge-cert-write-buffer.patch
#     patch -p1 < ../../mbedtls-ssl-server.patch
#     patch -p1 < ../../mbedtls-client.patch
#     RELEASE_TYPE=Release
#     [[ "$DEBUG" == "1" ]] && RELEASE_TYPE=Debug
#     cmake -DCMAKE_BUILD_TYPE=$RELEASE_TYPE -DENABLE_PROGRAMS=off -DCMAKE_CC_COMPILER=$CC -DCMAKE_C_FLAGS="-fPIC -DMBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION" . || exit 1
#     make -j`nproc` || exit 1
#     cmake -D CMAKE_INSTALL_PREFIX=$(readlink -f ../local) -P cmake_install.cmake || exit 1
#     popd
# fi

popd # deps

if [[ $VARIANT == "graphene" ]] ; then
    make deps/graphene/Runtime/pal-Linux-SGX
fi

if [ $VARIANT == "sgxsdk" ] ; then
    echo "Building wolfSSL SGX library ..."
    # The "make ... clean"s make sure there is no residual state from
    # previous builds lying around that might otherwise confuse the
    # build system.
    make -f ratls-wolfssl.mk clean || exit 1
    make -f ratls-wolfssl.mk || exit 1
    make -f ratls-wolfssl.mk clean || exit 1
fi

pushd deps
if [[ ! -d wolfssl-examples ]] ; then
    echo "Building SGX-SDK-based wolfSSL sample server (HTTPS) ..."
    
    git clone https://github.com/wolfSSL/wolfssl-examples.git || exit 1
    pushd wolfssl-examples
    git checkout 94b94262b45d264a40d484060cee595b26bdbfd7
    patch -p1 < ../../wolfssl-examples.patch || exit 1
    popd
fi
popd

echo "Building non-SGX-SDK sample clients ..."
make clients || exit 1
make clean || exit 1

if [ $VARIANT == "scone" ] ; then
    make scone-server || exit 1
fi

if [ $VARIANT == "sgxlkl" ] ; then
    make messages.pb-c.c
    make -C sgxlkl -j2 || exit 1
fi

if [ $VARIANT == "sgxsdk" ] ; then
    make sgxsdk-server || exit 1
fi

if [ $VARIANT == "graphene" ] ; then
    make graphene-server || exit 1
    make wolfssl-client-mutual || exit 1
fi
