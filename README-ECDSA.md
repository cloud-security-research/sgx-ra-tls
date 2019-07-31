# ECDSA-based Attestation

ECDSA-based attestation is an alternative to the EPID-based attestation model for environments where platform privacy is less of a concern and/or the specific deployment precludes interaction with external services (e.g., Intel Attestation Service) during the attestation process. The [ECDSA attestation white paper](https://software.intel.com/sites/default/files/managed/f1/b8/intel-sgx-support-for-third-party-attestation.pdf) provides additional information. In particular Section 3.1 describes the chain of trust from the platform-local attestation key to Intel.

For RA-TLS, the main impact of ECDSA-based attestation is the different attestation evidence embedded in the RA-TLS certificate. The [RA-TLS whitepaper](whitepaper.pdf) has more details on this.

## Prerequisites

Follow the official [installation instructions](https://01.org/intel-softwareguard-extensions/downloads/intel-sgx-dcap-linux-1.0.1-release) to prepare the system to compile the RA-TLS library and its sample programs. Ensure you can successfully run the [quote generation](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/SampleCode/QuoteGenerationSample) and [quote verification](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/QuoteVerification/Src) sample programs from the DCAP software distribution. Most notably, ECDSA attestation currently requires a different SGX kernel driver. Keep this in mind when switching between EPID and ECDSA.

In particular, the Intel SGX Data Center Attestation Primitives (DCAP) come with their own SGX driver and require the SGX SDK v2.4.

The Dockerfile [Dockerfile.template](Dockerfile.template) documents the software dependencies that must be installed on the system to successfully compile the RA-TLS library and its sample programs.

To use ECDSA-based attestation an [API token must be acquired](https://api.portal.trustedservices.intel.com/provisioning-certification). The registration process will provide a subscription key for the ECDSA-related API endpoints. The script [ra_tls_options.c.sh](ra_tls_options.c.sh) generates a C source file with these values. Either define the environment variables before building or invoke the script manually before building, i.e., `ECDSA_SUBSCRIPTION_KEY=... bash ra_tls_options.c.sh`. See [ra_tls_options.c.sh](ra_tls_options.c.sh) for the specific variable format. 

## Build

We provide a [Dockerfile template](Dockerfile.template) to build everything in a container. To create the Docker image issue ```make docker-image```. Because Graphene by default builds its kernel module, kernel headers are required. The make target specializes the template Dockerfile (Dockerfile-ecdsa.template) to include headers for the host's kernel version.

If the platform meets all the requirements for ECDSA-based attestation, EPID attestation should continue to work as expected. However, when switching between EPID and ECDSA, run "make mrproper" to reset the state before rebuilding the stack.

```
ECDSA=1 ./build.sh graphene && \
ECDSA=1 make wolfssl-ra-attester && \
ECDSA=1 make wolfssl-ra-challenger && \
make -C deps/SGXDataCenterAttestationPrimitives/SampleCode/QuoteServiceSample
```

Go get a coffee. It will take a while.

### Kernel Modules

Two Linux kernel modules must be loaded for SGX and Graphene.

The sources for the Intel SGX Linux driver for DCAP are located in ```deps/SGXDataCenterAttestationPrimitives/driver/linux/```. Build and load as usual: ```cd deps/SGXDataCenterAttestationPrimitives/driver/linux && make && sudo insmod intel_sgx.ko```

The Graphene driver sources are in ```deps/graphene/Pal/src/host/Linux-SGX/sgx-driver```. It is built automatically with the rest of Graphene. Load as usual: ```sudo insmod deps/graphene/Pal/src/host/Linux-SGX/sgx-driver/graphene-sgx.ko```

## Run

First, start the background service that connects application enclaves to the quoting enclave. The original DCAP library assumes a quoting enclave runs alongside each and every application enclave. To enable applications developed independently of the Intel SGX SDK to use the quoting enclave a service akin to AESMD is required for now.

```
deps/SGXDataCenterAttestationPrimitives/SampleCode/QuoteServiceSample/app &
```

We provide two sample programs to demonstrate ECDSA-based attestation within RA-TLS: An attester to generate an RA-TLS certificate and key; a challenger to verify the ECDSA-based RA-TLS certificate.

To run the attester execute

```
deps/graphene/Runtime/pal-Linux-SGX ./wolfssl-ra-attester ecdsa
```

This program outputs an ECDSA-based RA-TLS certificate and the corresponding private key in ```crt.der``` and ```key.der```, respectively.

To verify the RA-TLS certificate run

```
LD_LIBRARY_PATH=deps/local/lib ./wolfssl-ra-challenger crt.der
```
