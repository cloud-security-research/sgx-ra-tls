# Makefile to build the wolfSSL-based remote attestation TLS library.

######## Intel(R) SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
PROJECT_ROOT ?= $(shell readlink -f .)

WOLFSSL_ROOT := $(shell readlink -f deps/wolfssl)

SGX_COMMON_CFLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
    SGX_COMMON_CFLAGS += -O0 -g
else
    SGX_COMMON_CFLAGS += -O2
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Library_Name := sgx_ra_tls_wolfssl

Wolfssl_C_Extra_Flags := -DSGX_SDK -DWOLFSSL_SGX -DWOLFSSL_SGX_ATTESTATION -DUSER_TIME -DWOLFSSL_CERT_EXT

Wolfssl_C_Files := $(PROJECT_ROOT)/wolfssl-ra-attester.c \
	$(PROJECT_ROOT)/wolfssl-ra-challenger.c \
  $(PROJECT_ROOT)/sgxsdk-ra-attester_t.c \
  $(PROJECT_ROOT)/ra-challenger.c \
	$(PROJECT_ROOT)/wolfssl-ra.c \
	$(PROJECT_ROOT)/ra_tls_t.c \
  $(PROJECT_ROOT)/ra_tls_options.c

Wolfssl_Include_Paths := -I$(WOLFSSL_ROOT)/ \
						 -I$(WOLFSSL_ROOT)/wolfcrypt/ \
						 -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

Compiler_Warnings := -Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow -Werror
Flags_Just_For_C := -Wno-implicit-function-declaration -std=c11
Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Wolfssl_Include_Paths) -fno-builtin-printf -I.
Wolfssl_C_Flags := $(Compiler_Warnings) $(Flags_Just_For_C) $(Common_C_Cpp_Flags) $(Wolfssl_C_Extra_Flags)

Wolfssl_C_Objects := $(Wolfssl_C_Files:.c=.o)

override CFLAGS += $(Wolfssl_C_Flags)

.PHONY: all run clean mrproper

all: libsgx_ra_tls_wolfssl.a

######## Library Objects ########

ra_tls_t.c ra_tls_u.c ra_tls_t.h ra_tls_u.h : ra_tls.edl
	$(SGX_EDGER8R) $^ --search-path $(SGX_SDK)/include

libsgx_ra_tls_wolfssl.a: ra_tls_t.o ra_tls_u.o $(Wolfssl_C_Objects)
	ar rcs $@ $(Wolfssl_C_Objects)
	@echo "LINK =>  $@"

clean:
	@rm -f $(Wolfssl_C_Objects)

mrproper: clean
	@rm -f ra_tls_t.c ra_tls_t.h ra_tls_u.h ra_tls_u.c libsgx_ra_tls_wolfssl.a
