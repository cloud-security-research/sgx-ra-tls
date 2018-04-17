# Introduction

This project provides a proof-of-concept implementation on how to integrate Intel SGX remote attestation into the TLS connection setup. Conceptually, we extend the standard X.509 certificate with SGX-related information. The additional information allows the receiver of the certificate to verify that it is indeed communicating with an SGX enclave. The accompanying [white paper](whitepaper.pdf) "Integrating Remote Attestation with Transport Layer Security" provides more details.

## Repository Structure

The repository includes code to generate and parse extended X.509 certificates. The build system creates the following executables:

- Sample server (attester) 

    * using the SGX SDK based on [wolfSSL](deps/wolfssl-examples/SGX_Linux)
    * using [Graphene-SGX](https://github.com/oscarlab/graphene), [SCONE](https://sconedocs.github.io) or [SGX-LKL](https://github.com/lsds/sgx-lkl) based on [wolfSSL](deps/wolfssl-examples/tls/server-tls.c)
    * using [Graphene-SGX](https://github.com/oscarlab/graphene) based on [mbedtls](deps/mbedtls/programs/ssl/ssl_server.c)

- Non-SGX clients (challengers) based on different TLS libraries

    * [mbedtls](deps/mbedtls/programs/ssl/ssl_client1.c)
    * [wolfSSL](deps/wolfssl-examples/tls/client-tls.c)
    * [OpenSSL](openssl-client.c)

The code pertaining to the generation and parsing of extended X.509 certificates is located in the project's root directory.

## Code Structure

The code is split into two parts: the attester and the challenger. The challenger parses certificates, computes signatures and hashsums. The attester generates keys, certificates and interfaces with SGX. We have implementations based on two different cryptographic libraries: wolfSSL ([challenger](wolfssl-ra-challenger.c), [attester](wolfssl-ra-attester.c)) and mbedtls ([challenger](mbedtls-ra-challenger.c), [attester](mbedtls-ra-attester.c)).

The attester's code consists of [trusted](sgxsdk-ra-attester_t.c) and [untrusted](sgxsdk-ra-attester_u.c) SGX-SDK specific code to produce a quote using the SGX SDK. If the SGX SDK is not used, e.g., when using Graphene-SGX, there is code to [obtain the SGX quote](nonsdk-ra-attester.c) by directly communicating with the platform's architectural enclave.

Given a quote, there is [code to obtain an attestation verification report](ias-ra.c) from the Intel Attestation Service. This code uses libcurl and OpenSSL.

[An SGX SDK-based server](deps/wolfssl-examples/SGX_Linux) based on wolfSSL demonstrates how to use the [public attester API](ra-attester.h).

We provide three non-SGX clients ([mbedtls](deps/mbedtls/programs/ssl/ssl_client1.c), [wolfSSL](deps/wolfssl-examples/tls/client-tls.c), [OpenSSL](openssl-client.c)) to show how seamless remote attestation works with different TLS libraries. They use the public [challenger's API](ra-challenger.h). In principle, the client may also run in an enclave, but we provide no code for this at the moment.

# Build

We have tested the code with enclaves created using the Intel SGX SDK, Graphene-SGX, SCONE and SGX-LKL.

## Prerequisites

The code is tested with the SGX SDK (v2.0), SGX driver (v2.0) and SGX PSW (v2.0) installed on the host. Results may vary with different versions. Follow the [official instructions](https://01.org/intel-software-guard-extensions/downloads) to install the components and ensure they are working as intended. For Graphene-SGX, follow [their instructions](https://github.com/oscarlab/graphene/wiki/SGX-Quick-Start) to build and load the Graphene-SGX kernel module. Only the Graphene-SGX kernel module is required as a prerequisite. Graphene itself is built by the scripts.

[Register a (self-signed) certificate](https://software.intel.com/formfill/sgx-onboarding) to be able to connect to Intel's Attestation Service (IAS). The registration process will also assign you a software provider ID (SPID). It is recommended to store the private key and certificate in the file ias-client-key.pem and ias-client-cert.pem in the project's root directory. Otherwise, the paths in ra_tls_options.c, ssl-server.manifest and sgxlkl/ratls/Makefile must be updated accordingly.

In any case, you must update the SPID in [ra_tls_options.c](ra_tls_options.c) after registering with Intel.

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

where [binary] can be either mbedtls-ssl-server or wolfssl-ssl-server.

## SCONE

Similar to Graphene-SGX, we use socat to make AESM accessible over TCP/IP. SCONE can in principle to talk to AESM's named Unix socket directly, but support for this is currently not implemented.

    socat -t10 TCP-LISTEN:1234,bind=127.0.0.1,reuseaddr,fork,range=127.0.0.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket &

Next, execute the SCONE binary as such

    ./scone-wolfssl-ssl-server

## SGX-LKL

Set up the TAP device

    sudo ip tuntap add dev sgxlkl_tap0 mode tap user `whoami`
    sudo ip link set dev sgxlkl_tap0 up
    sudo ip addr add dev sgxlkl_tap0 10.0.1.254/24

Set up iptable rules for the SGX-LKL application to be able to reach the Internet. Replace [interface] with whatever interface connects you to the outside, e.g., eth0.

    sudo iptables -I FORWARD -i sgxlkl_tap0 -o [interface] -s 10.0.1.0/24 -m conntrack --ctstate NEW -j ACCEPT
    sudo iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -t nat -I POSTROUTING -o [interface] -j MASQUERADE

Start socat to make AESMD accessible over TCP/IP. Notice that we bind socat to the TAP interface's IP instead of the loopback as with Graphene-SGX and SCONE

    socat -t10 TCP-LISTEN:1234,bind=10.0.1.254,reuseaddr,fork,range=10.0.1.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket &

Finally, start the application

    SGXLKL_TAP=sgxlkl_tap0 SGXLKL_VERBOSE=1 RATLS_AESMD_IP=10.0.1.254 sgxlkl/sgx-lkl/build/sgx-lkl-run sgxlkl/sgx-lkl/apps/ratls/sgxlkl-miniroot-fs.img /sgxlkl-wolfssl-ssl-server

Use the openssl-client to connect to the server and print its SGX identity

    echo -n hello | ./openssl-client -p 11111 -h 10.0.1.1

Cleanup

    sudo iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
    sudo iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -D FORWARD -s 10.0.1.0/24 -i sgxlkl_tap0 -o eth0 -m conntrack --ctstate NEW -j ACCEPT
    sudo ip tuntap del dev sgxlkl_tap0 mode tap

## The clients

Execute any one of ./[wolfssl|mbedtls|openssl]-client in the project's root directory.

The openssl-client is most versatile as it allows to specify the IP and port to connect to via command line parameters.

Each client outputs a bunch of connection-related information, such as the server's SGX identity (MRENCLAVE, MRSIGNER). You can cross-check this with what the server reports in his output.
