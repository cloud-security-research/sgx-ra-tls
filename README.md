# Introduction

This project provides a proof-of-concept implementation on how to integrate Intel SGX remote attestation into the TLS connection setup. Conceptually, we extend the standard X.509 certificate with SGX-related information. The additional information allows the receiver of the certificate to verify that it is indeed communicating with an SGX enclave. The accompanying [white paper](whitepaper.pdf) "Integrating Remote Attestation with Transport Layer Security" provides more details.

## Repository Structure

The repository root directory contains code to generate and parse extended X.509 certificates. The build system creates the following executables:

- Sample server (attester) 

    * using the SGX SDK based on [wolfSSL](deps/wolfssl-examples/SGX_Linux)
    * using [Graphene-SGX](https://github.com/oscarlab/graphene), [SCONE](https://sconedocs.github.io) or [SGX-LKL](https://github.com/lsds/sgx-lkl) based on [wolfSSL](deps/wolfssl-examples/tls/server-tls.c)
    * using [Graphene-SGX](https://github.com/oscarlab/graphene) based on [mbedtls](deps/mbedtls/programs/ssl/ssl_server.c)
    * [Python-based HTTPS web server](sgxlkl/https-server/https-server.py) running on SGX-LKL

- Non-SGX clients (challengers) based on different TLS libraries

    * [mbedtls](deps/mbedtls/programs/ssl/ssl_client1.c)
    * [wolfSSL](deps/wolfssl-examples/tls/client-tls.c)
    * [OpenSSL](openssl-client.c)

- Graphene-SGX client and server doing mutual attestation

    * [server-tls.c](deps/wolfssl-examples/tls/server-tls.c)
    * [client-tls.c](deps/wolfssl-examples/tls/client-tls.c)

Some files may only exist after building the sources.

## Code Structure

The code is split into two parts: the attester and the challenger. The challenger parses certificates, computes signatures and hashsums. The attester generates keys, certificates and interfaces with SGX. We implemented the challenger and attester using two different cryptographic libraries: wolfSSL ([challenger](wolfssl-ra-challenger.c), [attester](wolfssl-ra-attester.c)) and mbedtls ([challenger](mbedtls-ra-challenger.c), [attester](mbedtls-ra-attester.c)).  We also provide an (OpenSSL-based challenger)[openssl-ra-challenger.c], but no attester. Note that the attester must communicate with the Intel Attestation Service and currently depends on OpenSSL to do this.

The attester's code consists of [trusted](sgxsdk-ra-attester_t.c) and [untrusted](sgxsdk-ra-attester_u.c) SGX-SDK specific code to produce a quote using the SGX SDK. If the SGX SDK is not used, e.g., when using Graphene-SGX, there is code to [obtain the SGX quote](nonsdk-ra-attester.c) by directly communicating with the platform's architectural enclave.

Given a quote, there is [code to obtain an attestation verification report](ias-ra.c) from the Intel Attestation Service. This code uses libcurl and OpenSSL.

[An SGX SDK-based server](deps/wolfssl-examples/SGX_Linux) based on wolfSSL demonstrates how to use the [public attester API](ra-attester.h).

We provide three non-SGX clients ([mbedtls](deps/mbedtls/programs/ssl/ssl_client1.c), [wolfSSL](deps/wolfssl-examples/tls/client-tls.c), [OpenSSL](openssl-client.c)) to show how seamless remote attestation works with different TLS libraries. They use the public [challenger's API](ra-challenger.h). There is one SGX client demonstrating mutual authentication (code: [client-tls.c](deps/wolfssl-examples/tls/client-tls.c), binary: wolfssl-client-mutual).

# Build

We have tested the code with enclaves created using the Intel SGX SDK, Graphene-SGX, SCONE and SGX-LKL.

## Prerequisites

The code is tested with the SGX SDK (v2.0), SGX driver (v2.0) and SGX PSW (v2.0) installed on the host. Results may vary with different versions. Follow the [official instructions](https://01.org/intel-software-guard-extensions/downloads) to install the components and ensure they are working as intended. For Graphene-SGX, follow [their instructions](https://github.com/oscarlab/graphene/wiki/SGX-Quick-Start) to build and load the Graphene-SGX kernel module. Only the Graphene-SGX kernel module is required as a prerequisite. Graphene itself is built by the scripts.

[Register a (self-signed) certificate](https://software.intel.com/formfill/sgx-onboarding) to be able to connect to Intel's Attestation Service (IAS). The registration process will also assign you a software provider ID (SPID). It is recommended to store the private key and certificate in the file ias-client-key.pem and ias-client-cert.pem in the project's root directory. Otherwise, the paths in ra_tls_options.c, ssl-server.manifest and sgxlkl/ratls/Makefile must be updated accordingly.

In any case, you must update the SPID and quote type (linkable vs unlinkable) in [ra_tls_options.c](ra_tls_options.c) after registering with Intel.

We support building the code in a Docker container. We provide a [Dockerfile](Dockerfile) to install all the required packages. If you prefer to build on your host system, the Dockerfile will guide you which packages and additional software to install. You can create an image based on the Dockerfile as such

    docker build -t ratls .

If you want to use SCONE and have access to their Docker images, edit the Dockerfile to use their image as the base instead of the default Ubuntu 16.04 (see first two lines of Dockerfile)

    docker build -t ratls-scone .

## Build instructions

The [build script](build.sh) creates executables based on either the Intel SGX SDK, Graphene-SGX, SCONE or SGX-LKL, depending on the first parameter

    ./build.sh sgxsdk|graphene|scone|sgxlkl

To build in a container using the Docker image created earlier, execute the following command in the project's root directory

    docker run --device=/dev/isgx --device=/dev/gsgx \
       --privileged=true \
       -v /var/run/aesmd:/var/run/aesmd \
       -v$(pwd):/project -it [Docker image] bash

where [Docker image] is the name of the Docker image created earlier, i.e., either ratls or ratls-scone. The parameter --privileged=true is only needed for SGX-LKL to be able to mount loopback devices and change iptables.

In the running container, change the directory and kick-off the build process

    cd /project
    ./build.sh sgxsdk|graphene|scone|sgxlkl

# Run

## Intel SGX SDK

To start the Intel SGX SDK based wolfSSL server execute

    ( cd deps/wolfssl-examples/SGX_Linux ; ./App -s )

With the server up and running, execute any of the [clients](#the-clients). If you are running in a container, you can get a 2nd console as follows (or run the server in the background by appending & at the end of the above command).

    docker ps

Use the container's ID with the following command for a 2nd console.

    docker exec -ti --user root [container id] bash

## Graphene-SGX

First, start a socat instance to make AESM's named Unix socket accessible over TCP/IP.

    socat -t10 TCP-LISTEN:1234,bind=127.0.0.1,reuseaddr,fork,range=127.0.0.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket &

Next, start the server application on Graphene-SGX

    SGX=1 ./deps/graphene/Runtime/pal_loader ./[binary]

where [binary] can be mbedtls-ssl-server, wolfssl-ssl-server or wolfssl-ssl-server-mutual.

## SCONE

Similar to Graphene-SGX, we use socat to make AESM accessible over TCP/IP. SCONE can in principle to talk to AESM's named Unix socket directly, but support for this is currently not implemented.

    socat -t10 TCP-LISTEN:1234,bind=127.0.0.1,reuseaddr,fork,range=127.0.0.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket &

Next, execute the SCONE binary as such

    ./scone-wolfssl-ssl-server

## SGX-LKL

To set up the TAP device (used by SGX-LKL for networking), iptables (required for SGX-LKL to be able to reach the internet) and starts an socat daemon (to talk to the host's AESMD). EXTERNAL_INTERFACE specifies your "external" interface (typically eth0), i.e., the one which connects you to the internet.

    EXTERNAL_IFACE=eth0 make -C sgxlkl up-sgxlkl-network

We provide two applications for SGX-LKL. First, a simple server based on wolfssl. This is similar to the examples provided for the other systems. Use Ctrl-C to stop the server.

    make -C sgxlkl run-wolfssl-server

Use the openssl-client to connect to the server and print its SGX identity

    echo -n hello | ./openssl-client -p 11111 -h 10.0.1.1

Second, there is a [Python-based HTTPS server](sgxlkl/https-server/https-server.py). We preload (LD_PRELOAD) a library with the server. The [preloaded library's](sgxlkl/ldpreload.c) initialization routine writes the key and certificate to /tmp/key and /tmp/crt, respectively. The server reads the RA-TLS key and certificate from the file system instead of calling the library directly.

    make -C sgxlkl run-https-server

Warnings about LD_PRELOAD not being able to find /ldpreload.so can be ignored. LD_PRELOAD is also applied to the sgx-lkl-run binary, but ldpreload.so only exists within the LKL environment. The server listens on 10.0.1.1:4443. Using the RA-TLS-aware openssl-client you can connect to it as such

    ./openssl-client -p 4443 -h 10.0.1.1

To stop socat, remove iptable rules and the TAP interface issue

    EXTERNAL_IFACE=eth0 make -C sgxlkl down-sgxlkl-network

## The clients

### Non-SGX clients

Execute any one of the non-SGX binaries wolfssl-client, mbedtls-client or openssl-client in the project's root directory.
The openssl-client is most versatile as it allows to specify the IP and port to connect to via command line parameters.
Each client outputs a bunch of connection-related information, such as the server's SGX identity (MRENCLAVE, MRSIGNER). You can cross-check this with what the server reports in its output.

### SGX client

The Graphene-SGX client wolfssl-client-mutual only works in combination with wolfssl-ssl-server-mutual.

    SGX=1 ./deps/graphene/Runtime/pal_loader ./wolfssl-client-mutual
