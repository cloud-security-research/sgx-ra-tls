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

mkdir -p deps
make -j`nproc` deps
pushd deps

# The OpenSSL, wolfSSL, mbedtls libraries are necessary for the non-SGX
# clients. We do not use their package versions since we need them to
# be compiled with specific flags.

if [[ ! -d mbedtls ]] ; then
    git clone https://github.com/ARMmbed/mbedtls.git
    pushd mbedtls
    git checkout mbedtls-2.5.1
    # Add  -DCMAKE_BUILD_TYPE=Debug for Debug
    patch -p1 < ../../mbedtls-enlarge-cert-write-buffer.patch
    patch -p1 < ../../mbedtls-ssl-server.patch
    patch -p1 < ../../mbedtls-client.patch
    cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_PROGRAMS=off -DCMAKE_CC_COMPILER=$CC -DCMAKE_C_FLAGS="-fPIC -O2 -DMBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION" . || exit 1
    make -j`nproc` || exit 1
    cmake -D CMAKE_INSTALL_PREFIX=$(readlink -f ../local) -P cmake_install.cmake || exit 1
    popd
fi

if [[ ! -d zlib ]] ; then
    git clone https://github.com/madler/zlib.git
    pushd zlib
    CFLAGS="-fPIC -O2" ./configure --prefix=$(readlink -f ../local) --static
    make install
    popd
fi

if [[ ! -d protobuf-c ]] ; then
    git clone https://github.com/protobuf-c/protobuf-c.git
    pushd protobuf-c
    ./autogen.sh
    CFLAGS="-fPIC -O2" ./configure --prefix=$(readlink -f ../local) --disable-shared
    make protobuf-c/libprotobuf-c.la
    cp protobuf-c/.libs/libprotobuf-c.a ../local/lib
    mkdir ../local/include/protobuf-c
    cp protobuf-c/protobuf-c.h ../local/include/protobuf-c
    popd
fi

# Linux SGX SDK code
if [[ ! -d linux-sgx ]] ; then
    git clone https://github.com/01org/linux-sgx.git
    pushd linux-sgx
    git checkout sgx_2.0
    popd
fi

if [[ ! -d linux-sgx-driver && $VARIANT == "graphene" ]] ; then
     git clone https://github.com/01org/linux-sgx-driver.git
     pushd linux-sgx-driver
     git checkout sgx_driver_2.0
     popd
fi

if [[ ! -d graphene && $VARIANT == "graphene" ]] ; then
    git clone --recursive https://github.com/oscarlab/graphene.git
    pushd graphene
    git checkout e01769337c38f67d7ccd7a7cadac4f9df0c6c65e
    openssl genrsa -3 -out Pal/src/host/Linux-SGX/signer/enclave-key.pem 3072
    # patch -p1 < ../../graphene-sgx-linux-driver-2.1.patch
    # The Graphene build process requires two inputs: (i) SGX driver directory, (ii) driver version.
    # Unfortunately, cannot use make -j`nproc` with Graphene's build process :(
    printf "$(readlink -f ../linux-sgx-driver)\n2.0\n" | make SGX=1 || exit 1

    # I prefer to have all dynamic libraries in one directory. This
    # reduces the effort in the Graphene-SGX manifest file.
    ln -s /usr/lib/x86_64-linux-gnu/libprotobuf-c.so.1 Runtime/
    ln -s /usr/lib/libsgx_uae_service.so Runtime/
    ln -s /lib/x86_64-linux-gnu/libcrypto.so.1.0.0 Runtime/
    ln -s /lib/x86_64-linux-gnu/libz.so.1 Runtime/
    ln -s /lib/x86_64-linux-gnu/libssl.so.1.0.0 Runtime/
    
    popd
fi

popd # deps

# Copy client certificates required to talk to Intel's Attestation
# Service
# cp ../../certs/ias-client*.pem .

if [ $VARIANT == "sgxsdk" ] ; then
    echo "Building wolfSSL SGX library ..."
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
    # Copy certificates required to talk to Intel Attestation Service
    ln -s ../../../ias-client-key.pem SGX_Linux/ias-client-key.pem
    ln -s ../../../ias-client-cert.pem SGX_Linux/ias-client-cert.pem
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
    make -C sgxlkl -j2 || exit 1
fi

if [ $VARIANT == "sgxsdk" ] ; then
    make sgxsdk-server || exit 1
fi

if [ $VARIANT == "graphene" ] ; then
    make graphene-server || exit 1
    make wolfssl-client-mutual || exit 1
fi
