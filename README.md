# Introduction

This project provides a proof-of-concept implementation on how to integrate Intel SGX remote attestation into the TLS connection setup. Conceptually, we extend the standard X.509 certificate with SGX-related information. The additional information allows the receiver of the certificate to verify that it is indeed communicating with an SGX enclave. The accompanying [white paper](whitepaper.pdf) "Integrating Remote Attestation with Transport Layer Security" provides more details.

## Repository Structure

The repository includes code to generate and parse extended X.509 certificates. The build system creates the following executables:

- Sample server (attester) 

    * using the SGX SDK based on [wolfSSL](deps/wolfssl-examples/SGX_Linux)
    * using [Graphene-SGX](https://github.com/oscarlab/graphene) or [SCONE](https://sconedocs.github.io) based on [wolfSSL](deps/wolfssl-examples/tls/server-tls.c)
    * using [Graphene-SGX](https://github.com/oscarlab/graphene) or [SCONE](https://sconedocs.github.io) based on [mbedtls](deps/mbedtls/programs/ssl/ssl_server.c)

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

We have tested the code with enclaves created using the Intel SGX SDK, Graphene-SGX and SCONE.

## Prerequisites

The code is tested with the SGX SDK (v2.0), SGX driver (v2.0) and SGX PSW (v2.0) installed on the host. Results may vary with different versions. Follow the [official instructions](https://01.org/intel-software-guard-extensions/downloads) to install the components and ensure they are working as intended. For Graphene-SGX, follow [their instructions](https://github.com/oscarlab/graphene/wiki/SGX-Quick-Start) to build and load the Graphene-SGX kernel module. Only the Graphene-SGX kernel module is required as a prerequisite. Graphene itself is built by the scripts.

[Register a (self-signed) certificate](https://software.intel.com/formfill/sgx-onboarding) to be able to connect to Intel's Attestation Service (IAS). The registration process will also assign you a software provider ID (SPID). It is recommended to store the private key and certificate in the file ias-client-key.pem and ias-client-cert.pem in the project's root directory. Otherwise, the paths in ra_tls_options.c and ssl-server.manifest must be updated accordingly.

In any case, you must update the SPID in [ra_tls_options.c](ra_tls_options.c) after registering with Intel.

We recommend building the code in a container. We provide a [Dockerfile](Dockerfile) to install all the required packages. If you prefer to build on your host system, the Dockerfile will guide you which packages and additional software to install. You can create an image based on the Dockerfile as such

    docker build -f ./Dockerfile -t ratls

If you want to use SCONE and have access to their Docker images, edit the Dockerfile to use their image as the base instead of the default Ubuntu 16.04 (see first two lines of Dockerfile)

    docker build -f ./Dockerfile -t ratls-scone

## Build instructions

The [build script](build.sh) creates executables based on either the Intel SGX SDK, Graphene-SGX or SCONE, depending on the first parameter

    ./build.sh sgxsdk|graphene|scone

To build in a container using the Docker image created earlier, execute the following command in the project's root directory

    docker run --device=/dev/isgx --device=/dev/gsgx -v /var/run/aesmd:/var/run/aesmd \
       -v$(pwd):/project -it [Docker image] bash

where [Docker image] is the name of the Docker image we created earlier, i.e., either ratls or ratls-scone.

In the running container, change the directory and kick-off the build process

    cd /project
    ./build.sh sgxsdk|graphene|scone

# Run

## Intel SGX SDK based server

To start the wolfSSL-based SGX server run.

       ( cd deps/wolfssl-examples/SGX_Linux ; ./App -s )

With the server up and running, execute any of the [clients](#the-clients). If you are running in a container, you can get a 2nd console as follows (or run the server in the background by appending & at the end of the above command).

       docker ps

Use the container's ID with the following command for a 2nd console.

       docker exec -ti --user root [container id] bash

## Graphene-SGX based server

First, start an socat instance to make AESM's named Unix socket accessible over TCP/IP.

       socat -t10 TCP-LISTEN:1234,bind=127.0.0.1,reuseaddr,fork,range=127.0.0.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket &

Next, start the server application on Graphene-SGX

       SGX=1 ./deps/graphene/Runtime/pal_loader ./[binary]

where [binary] can be either mbedtls-ssl-server or wolfssl-ssl-server.

## SCONE based server

Similar to Graphene-SGX, we currently require an socat instance to communicate with AESM. In contrast to Graphene-SGX, SCONE should be able to talk to AESM's named socket directly, but we do not have an extra code path for SCONE.

       socat -t10 TCP-LISTEN:1234,bind=127.0.0.1,reuseaddr,fork,range=127.0.0.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket &

Next, execute the SCONE binary as such

       ./scone-wolfssl-ssl-server

## The clients

Execute any one of ./[wolfssl|mbedtls|openssl]-client in the project's root directory.

Each client outputs a bunch of connection-related information, such as the server's SGX identity (MRENCLAVE, MRSIGNER). You can cross-check this with what the server reports in his output.
