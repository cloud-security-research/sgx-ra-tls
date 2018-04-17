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

mkdir -p deps
pushd deps

# The wolfSSL and mbedtls libraries are necessary for the non-SGX
# clients. We do not use their package versions since we need them to
# be compiled with specific flags.

if [ ! -d mbedtls ] ; then
    git clone https://github.com/ARMmbed/mbedtls.git
    pushd mbedtls
    git checkout mbedtls-2.5.1
    # Add  -DCMAKE_BUILD_TYPE=Debug for Debug
    patch -p1 < ../../mbedtls-enlarge-cert-write-buffer.patch
    patch -p1 < ../../mbedtls-ssl-server.patch
    patch -p1 < ../../mbedtls-client.patch
    cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_PROGRAMS=off -DCMAKE_C_FLAGS="-fPIC -DMBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION" . || exit 1
    make -j`nproc` || exit 1
    cmake -D CMAKE_INSTALL_PREFIX=$(readlink -f ../local) -P cmake_install.cmake || exit 1
    popd
fi

if [ ! -d wolfssl ] ; then
    git clone https://github.com/wolfSSL/wolfssl || exit 1
    pushd wolfssl
    git checkout 57e5648a5dd734d1c219d385705498ad12941dd0
    patch -p1 < ../../wolfssl-sgx-attestation.patch || exit 1
    [ ! -f ./configure ] && ./autogen.sh
    # Add --enable-debug for debug build
    # --enable-nginx: #define's WOLFSSL_ALWAYS_VERIFY_CB and
    # KEEP_OUR_CERT. Without this there seems to be no way to access
    # the certificate after the handshake.
    # 
    # 2017-12-11: --enable-nginx also activates OPENSSLEXTRA. The later
    # includes symbols that clash with OpenSSL, i.e., wolfSSL and OpenSSL
    # cannot be linked into the same binary. --enable-opensslcoexists does
    # not seem to help in this case.
    WOLFSSL_CFLAGS="-fPIC -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_ALWAYS_VERIFY_CB -DKEEP_PEER_CERT"
    CFLAGS="$WOLFSSL_CFLAGS" ./configure --prefix=$(readlink -f ../local) --enable-writedup --enable-static --enable-keygen --enable-certgen --enable-certext || exit 1 # --enable-debug
    make -j`nproc` || exit 1
    make install || exit 1
    # Add -DDEBUG_WOLFSSL to CFLAGS for debug
    pushd IDE/LINUX-SGX
    make -f sgx_t_static.mk SGX_DEBUG=1 CFLAGS="-DUSER_TIME -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_KEY_GEN -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT" || exit 1
    cp libwolfssl.sgx.static.lib.a ../../../local/lib
    popd
    popd
fi

if [[ ! -d curl && "$VARIANT" != "scone" && "$VARIANT" != "sgxlkl" ]] ; then
    git clone https://github.com/curl/curl.git
    pushd curl
    git checkout curl-7_47_0
    ./buildconf
    ./configure --prefix=$(readlink -f ../local) --without-libidn --without-librtmp --without-libssh2 --without-libmetalink --without-libpsl --with-ssl # --enable-debug
    make -j`nproc` || exit 1
    make install || exit 1
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
    git checkout 7807773a76c765d9e0839e30ba5f029dfcb3d0fb
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
make clean || exit

if [ $VARIANT == "scone" ] ; then
    bash ./build-SCONE.sh || exit 1
    make scone-server || exit 1
fi

if [ $VARIANT == "sgxlkl" ] ; then
    bash ./build-sgxlkl.sh || exit 1
fi

[ $VARIANT == "sgxsdk" ] && make sgxsdk-server
[ $VARIANT == "graphene" ] && make graphene-server
