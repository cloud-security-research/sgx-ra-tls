#!/bin/bash

mkdir -p sgxlkl/deps

pushd sgxlkl

git clone https://github.com/lsds/sgx-lkl.git
( cd sgx-lkl ; make )
cp -a ratls sgx-lkl/apps

pushd deps

wget https://git.musl-libc.org/cgit/musl/snapshot/musl-1.1.19.tar.gz
tar xfz musl-1.1.19.tar.gz
pushd musl-1.1.19
./configure --prefix=$(readlink -f ../../local)
make -j8
make install
popd

CC=$(readlink -f ../local/bin/musl-gcc)

git clone https://github.com/openssl/openssl.git
pushd openssl
git checkout OpenSSL_1_0_2g
CC=$CC ./config --prefix=$(readlink -f ../../local) no-shared
make -j8
make install
popd

git clone https://github.com/madler/zlib.git
pushd zlib
CC=$CC ./configure --prefix=$(readlink -f ../../local) --static
make install
popd

git clone https://github.com/curl/curl.git
pushd curl
# This curl version seems to work in combination with Intel's HTTPS proxy ...
git checkout curl-7_47_0
./buildconf
CC=$CC ./configure --prefix=$(readlink -f ../../local) --without-libidn --without-librtmp --without-libssh2 --without-libmetalink --without-libpsl --with-ssl=$(readlink -f ../../local) --disable-shared
make -j8
make install
popd

git clone https://github.com/protobuf-c/protobuf-c.git
pushd protobuf-c
./autogen.sh
CC=$CC ./configure --prefix=$(readlink -f ../../local) --disable-shared
make protobuf-c/libprotobuf-c.la
cp protobuf-c/.libs/libprotobuf-c.a ../../local/lib
mkdir ../../local/include/protobuf-c
cp protobuf-c/protobuf-c.h ../../local/include/protobuf-c
popd

git clone https://github.com/wolfSSL/wolfssl || exit 1
pushd wolfssl
git checkout 57e5648a5dd734d1c219d385705498ad12941dd0
patch -p1 < ../../../wolfssl-sgx-attestation.patch || exit 1
[ ! -f ./configure ] && ./autogen.sh
WOLFSSL_CFLAGS="-DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_ALWAYS_VERIFY_CB -DKEEP_PEER_CERT"
CFLAGS="$WOLFSSL_CFLAGS" CC=$CC ./configure --prefix=$(readlink -f ../../local) --enable-writedup --enable-static --disable-shared --enable-keygen --enable-certgen --enable-certext || exit 1 # --enable-debug
make install || exit 1

popd # wolfssl
popd # deps
popd # sgxlkl

make sgxlkl-wolfssl-ssl-server

# USER=`whoami` is required only within Docker containers. SGX-LKL's
# Makefile uses the variable, but it's not typically set in a Docker
# container.
( cd sgxlkl/sgx-lkl/apps/ratls && USER=`whoami` make )
