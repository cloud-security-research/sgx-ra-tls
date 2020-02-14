# Makefile to build non-SGX-SDK-based RA-TLS client and server
# programs.

export SGX_SDK?=/opt/intel/sgxsdk

SGX_DCAP_URI=https://github.com/intel/SGXDataCenterAttestationPrimitives
SGX_DCAP_COMMIT=bfab1376480f760757738092399d0d99b22f4dfd
SGX_DCAP?=deps/SGXDataCenterAttestationPrimitives/

SGX_DCAP_INC=-I$(SGX_DCAP)/QuoteGeneration/quote_wrapper/common/inc -I$(SGX_DCAP)/QuoteGeneration/pce_wrapper/inc -I$(SGX_DCAP)/QuoteVerification/Src/AttestationLibrary/include

CFLAGS+=-std=gnu99 -I. -I$(SGX_SDK)/include -Ideps/local/include $(SGX_DCAP_INC) -fPIC
CFLAGSERRORS=-Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow -Werror
CFLAGS+=$(CFLAGSERRORS) -g -O0 -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_CERT_EXT # -DDEBUG -DDYNAMIC_RSA
CFLAGS+=-DSGX_GROUP_OUT_OF_DATE

# On Ubuntu 18.04 executables are built as position independent
# executables (PIE) by default. Position independent executables give
# Graphene trouble. Once this is fixed, we can potentially remove this
# link flag again.
LDFLAGS_GRAPHENE_QUIRKS=-no-pie

ifdef ECDSA
CFLAGS+=-DRATLS_ECDSA
endif

LIBS=mbedtls/libra-attester.a \
	mbedtls/libnonsdk-ra-attester.a \
	mbedtls/libra-challenger.a \
	mbedtls/libra-tls.so \
	wolfssl/libra-challenger.a \
	wolfssl/libnonsdk-ra-attester.a \
	wolfssl/libra-attester.a \
	wolfssl/libra-tls.so \
	openssl/libra-challenger.a \
	openssl/libnonsdk-ra-attester.a

.PHONY: all
all: $(LIBS)

WOLFSSL_CLIENT_LIBS=-l:libra-challenger.a -l:libwolfssl.a -lm
ifdef ECDSA
WOLFSSL_CLIENT_LIBS+=-l:libQuoteVerification.so -ldl
wolfssl-client: deps/local/lib/libQuoteVerification.so
endif
wolfssl-client: deps/wolfssl-examples/tls/client-tls.c wolfssl/libra-challenger.a
	$(CC) -o $@ $(filter %.c, $^) $(CFLAGS) -Lwolfssl -Ldeps/local/lib $(WOLFSSL_CLIENT_LIBS)

ra_tls_options.c: ra_tls_options.c.sh
	bash $^ > $@

wolfssl-client-mutual: deps/wolfssl-examples/tls/client-tls.c ra_tls_options.c wolfssl/libra-challenger.a wolfssl/libnonsdk-ra-attester.a
	$(CC) -o $@ $(filter %.c, $^) $(CFLAGS) $(LDFLAGS_GRAPHENE_QUIRKS) -DSGX_RATLS_MUTUAL -Ldeps/local/lib $(filter %.a, $^) $(WOLFSSL_SSL_SERVER_LIBS) $(SGX_DCAP_LIB)
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal deps/graphene/Runtime/libpal-Linux-SGX.so -key deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -exec $@ -manifest ssl-server.manifest
ifndef ECDSA
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig
endif

mbedtls-client : deps/mbedtls/programs/ssl/ssl_client1.c mbedtls/libra-challenger.a
	$(CC) -o $@ $(filter %.c, $^) $(CFLAGS) -Lmbedtls -Ldeps/local/lib -l:libra-challenger.a -l:libmbedtls.a -l:libmbedx509.a -l:libmbedcrypto.a

openssl-client : openssl-client.c openssl/libra-challenger.a
	$(CC) -o $@ $(filter %.c, $^) $(CFLAGS) -Lopenssl -Ldeps/local/lib -l:libra-challenger.a -l:libssl.a -l:libcrypto.a -lm -ldl

mbedtls:
	mkdir -p $@

wolfssl:
	mkdir -p $@

openssl:
	mkdir -p $@

mbedtls-ra-attester.o mbedtls-ra-challenger.o ias-ra-mbedtls.o: deps/local/lib/libmbedtls.a

mbedtls/libra-challenger.a : mbedtls ra.o mbedtls-ra-challenger.o ra-challenger.o ias_sign_ca_cert.o
	$(AR) rcs $@ $(filter %.o, $^)

mbedtls/libra-attester.a : mbedtls ra.o mbedtls-ra-attester.o ias-ra-mbedtls.o
	$(AR) rcs $@ $(filter %.o, $^)

mbedtls/libnonsdk-ra-attester.a : mbedtls ra.o mbedtls-ra-attester.o ias-ra-mbedtls.o nonsdk-ra-attester.o messages.pb-c.o sgx_report.o
	$(AR) rcs $@ $(filter %.o, $^)

nonsdk-ra-attester.o: messages.pb-c.c

mbedtls/libra-tls.so : mbedtls ra.o mbedtls-ra-challenger.o ra-challenger.o ias_sign_ca_cert.o mbedtls-ra-attester.o ias-ra-openssl.o nonsdk-ra-attester.o messages.pb-c.o sgx_report.o
	$(CC) -shared -o $@ $(filter %.o, $^) -Ldeps/local/lib -l:libcurl-openssl.a -l:libmbedtls.a -l:libmbedx509.a -l:libmbedcrypto.a -l:libprotobuf-c.a -l:libz.a -l:libssl.a -l:libcrypto.a -ldl

wolfssl/libra-challenger.a: wolfssl ra.o wolfssl-ra-challenger.o wolfssl-ra.o ra-challenger.o ias_sign_ca_cert.o ecdsa-sample-data/real/sample_data.o
	$(AR) rcs $@ $(filter %.o, $^)

ias-ra-%.c: ias-ra.c
	cp $< $@

ias-ra-openssl.o: CFLAGS += -DUSE_OPENSSL
ias-ra-openssl.o: deps/local/lib/libcurl-openssl.a
ias-ra-wolfssl.o: CFLAGS += -DUSE_WOLFSSL
ias-ra-wolfssl.o: deps/local/lib/libcurl-wolfssl.a
ias-ra-mbedtls.o: CFLAGS += -DUSE_MBEDTLS
ias-ra-mbedtls.o: deps/local/lib/libcurl-mbedtls.a

wolfssl-ra-attester.o: ecdsa-sample-data/real/sample_data.h ecdsa-attestation-collateral.h
wolfssl-ra-challenger.o: ecdsa-sample-data/real/sample_data.h

wolfssl/libra-attester.a: wolfssl wolfssl-ra-attester.o wolfssl-ra.o ias-ra-wolfssl.o
	$(AR) rcs $@ $(filter %.o, $^)

ecdsa-ra-attester.o: ecdsa-aesmd-messages.pb-c.c

ifdef ECDSA
wolfssl/libnonsdk-ra-attester.a: ecdsa-aesmd-messages.pb-c.o ecdsa-ra-attester.o ecdsa-sample-data/real/sample_data.o ecdsa-attestation-collateral.o
endif
wolfssl/libnonsdk-ra-attester.a: wolfssl ra.o wolfssl-ra.o wolfssl-ra-attester.o ias-ra-wolfssl.o nonsdk-ra-attester.o messages.pb-c.o sgx_report.o
		$(AR) rcs $@ $(filter %.o, $^)

wolfssl/libra-tls.so: wolfssl ra.o wolfssl-ra-challenger.o wolfssl-ra.o ra-challenger.o ias_sign_ca_cert.o wolfssl-ra-attester.o ias-ra-wolfssl.o nonsdk-ra-attester.o messages.pb-c.o sgx_report.o
	$(CC) -shared -o $@ $(filter %.o, $^) -Ldeps/local/lib -l:libcurl-wolfssl.a -l:libwolfssl.a -l:libprotobuf-c.a -l:libz.a -l:libssl.a -l:libcrypto.a -ldl

openssl/libra-challenger.a: openssl ra.o ra-challenger.o openssl-ra-challenger.o ias_sign_ca_cert.o
	$(AR) rcs $@ $(filter %.o, $^)

openssl/libnonsdk-ra-attester.a: openssl ra.o openssl-ra-attester.o ias-ra-openssl.o nonsdk-ra-attester.o messages.pb-c.o sgx_report.o
	$(AR) rcs $@ $(filter %.o, $^)

SGX_GIT=deps/linux-sgx
EPID_SDK=$(SGX_GIT)/external/epid-sdk

CFLAGS+=-I$(SGX_GIT)/common/inc/internal -I$(EPID_SDK) -I$(SGX_GIT)/common/inc

WOLFSSL_RA_ATTESTER_SRC=wolfssl-ra-attester.c wolfssl-ra.c
MBEDTLS_RA_ATTESTER_SRC=mbedtls-ra-attester.c ra-challenger.c
MBEDTLS_RA_CHALLENGER_SRC=mbedtls-ra-challenger.c ias_sign_ca_cert.c
NONSDK_RA_ATTESTER_SRC=nonsdk-ra-attester.c messages.pb-c.c sgx_report.S

ecdsa-aesmd-messages.pb-c.c:
	cp $(SGX_DCAP)/SampleCode/QuoteServiceSample/App/ecdsa-aesmd-messages.proto .
	protoc-c ecdsa-aesmd-messages.proto --c_out=.

messages.pb-c.c:
	( cd deps/linux-sgx/psw/ae/common/proto/ ; protoc-c messages.proto --c_out=. )
	cp deps/linux-sgx/psw/ae/common/proto/messages.pb-c.c deps/linux-sgx/psw/ae/common/proto/messages.pb-c.h .

#### HTTPS server based on mbedtls and wolfSSL. Use with Graphene-SGX.

SSL_SERVER_INCLUDES=-I. -I$(SGX_SDK)/include -Ideps/local/include \
	-Ideps/linux-sgx/common/inc/internal \
  -Ideps/linux-sgx/external/epid-sdk \
  -I$(SGX_GIT)/common/inc

MBEDTLS_SSL_SERVER_SRC=deps/mbedtls/programs/ssl/ssl_server.c \
	ra_tls_options.c ra.c \
	$(MBEDTLS_RA_ATTESTER_SRC) $(MBEDTLS_RA_CHALLENGER_SRC) \
	$(NONSDK_RA_ATTESTER_SRC) ias-ra-mbedtls.o
MBEDTLS_SSL_SERVER_LIBS=-l:libcurl-mbedtls.a -l:libmbedx509.a -l:libmbedtls.a -l:libmbedcrypto.a -l:libprotobuf-c.a -l:libz.a

mbedtls-ssl-server: $(MBEDTLS_SSL_SERVER_SRC) ssl-server.manifest deps/graphene/Runtime/pal_loader
	$(CC) $(MBEDTLS_SSL_SERVER_SRC) -o $@ $(CFLAGSERRORS) $(LDFLAGS_GRAPHENE_QUIRKS) $(SSL_SERVER_INCLUDES) -Ldeps/local/lib/ $(MBEDTLS_SSL_SERVER_LIBS)
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal deps/graphene/Runtime/libpal-Linux-SGX.so -key deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -exec $@ -manifest ssl-server.manifest
ifndef ECDSA
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig
endif

WOLFSSL_SSL_SERVER_SRC=deps/wolfssl-examples/tls/server-tls.c ra_tls_options.c

WOLFSSL_SSL_SERVER_LIBS=-l:libcurl-wolfssl.a -l:libwolfssl.a -l:libprotobuf-c.a -l:libz.a -lm -ldl

wolfssl-ssl-server: $(WOLFSSL_SSL_SERVER_SRC) ssl-server.manifest deps/graphene/Runtime/pal_loader wolfssl/libnonsdk-ra-attester.a
	$(CC) -o $@ $(CFLAGSERRORS) $(LDFLAGS_GRAPHENE_QUIRKS) $(SSL_SERVER_INCLUDES) -Ldeps/local/lib -L. -Lwolfssl $(WOLFSSL_SSL_SERVER_SRC) -l:libnonsdk-ra-attester.a $(WOLFSSL_SSL_SERVER_LIBS)
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal deps/graphene/Runtime/libpal-Linux-SGX.so -key deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -exec $@ -manifest ssl-server.manifest
ifndef ECDSA
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig
endif

ifdef ECDSA
WOLFSSL_SSL_SERVER_LIBS+= -l:libQuoteVerification.so -ldl
endif
wolfssl-ssl-server-mutual: deps/wolfssl-examples/tls/server-tls.c ra_tls_options.c ssl-server.manifest deps/graphene/Runtime/pal_loader wolfssl/libra-challenger.a wolfssl/libnonsdk-ra-attester.a
	$(CC) -o $@ $(CFLAGSERRORS) $(LDFLAGS_GRAPHENE_QUIRKS) -DSGX_RATLS_MUTUAL $(SSL_SERVER_INCLUDES) $(filter %.c, $^) -Ldeps/local/lib $(SGX_DCAP_LIB) wolfssl/libra-challenger.a wolfssl/libnonsdk-ra-attester.a $(WOLFSSL_SSL_SERVER_LIBS)
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal deps/graphene/Runtime/libpal-Linux-SGX.so -key deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -exec $@ -manifest ssl-server.manifest
ifndef ECDSA
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig
endif

libsgx_ra_tls_wolfssl.a:
	make -f ratls-wolfssl.mk
	rm -f wolfssl-ra-challenger.o wolfssl-ra.o ra-challenger.o ias_sign_ca_cert.o  # BUGFIX: previous Makefile compiles these .o files with incorrect C flags

deps/wolfssl-examples/SGX_Linux/App: deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a libsgx_ra_tls_wolfssl.a sgxsdk-ra-attester_u.c ias-ra.c
ifndef ECDSA
	cp sgxsdk-ra-attester_u.c ias-ra.c deps/wolfssl-examples/SGX_Linux/untrusted
	$(MAKE) -C deps/wolfssl-examples/SGX_Linux SGX_MODE=HW SGX_DEBUG=1 SGX_WOLFSSL_LIB=$(shell readlink -f deps/wolfssl/IDE/LINUX-SGX) SGX_SDK=$(SGX_SDK) WOLFSSL_ROOT=$(shell readlink -f deps/wolfssl) SGX_RA_TLS_LIB=$(shell readlink -f .)
endif

%.html: %.md
	pandoc --from markdown_github --to html --standalone $< --output $@

.PHONY: html
html: README.html README-ECDSA.html

SCONE_SSL_SERVER_INCLUDES=-I. -I$(SGX_SDK)/include -ISCONE/deps/local/include \
	-Ideps/linux-sgx/common/inc/internal \
  -Ideps/linux-sgx/external/epid-sdk \
  -I$(SGX_GIT)/common/inc

SGXLKL_SSL_SERVER_INCLUDES=-I. -I$(SGX_SDK)/include \
  -Isgxlkl/local/include \
	-Ideps/linux-sgx/common/inc/internal \
  -Ideps/linux-sgx/external/epid-sdk \
  -I$(SGX_GIT)/common/inc

clients: mbedtls-client wolfssl-client openssl-client
graphene-server: wolfssl-ssl-server mbedtls-ssl-server wolfssl-ssl-server-mutual
scone-server: scone-wolfssl-ssl-server
sgxsdk-server: deps/wolfssl-examples/SGX_Linux/App

scone-wolfssl-ssl-server: $(WOLFSSL_SSL_SERVER_SRC)
	/usr/local/bin/scone-gcc -o $@ $(CFLAGSERRORS) $(SCONE_SSL_SERVER_INCLUDES) -LSCONE/deps/local/lib $(WOLFSSL_SSL_SERVER_SRC) $(WOLFSSL_SSL_SERVER_LIBS)

# SGX-LKL requires position independent code (flags: -fPIE -pie) to
# map the binary anywhere in the address space.
sgxlkl-wolfssl-ssl-server: CFLAGS+=-DUSE_WOLFSSL
sgxlkl-wolfssl-ssl-server: $(WOLFSSL_SSL_SERVER_SRC)
	sgxlkl/sgx-lkl/build/host-musl/bin/musl-gcc -o $@ -fPIE -pie $(CFLAGS) $(CFLAGSERRORS) $(SGXLKL_SSL_SERVER_INCLUDES) -Lsgxlkl/local/lib $(WOLFSSL_SSL_SERVER_SRC) $(NONSDK_RA_ATTESTER_SRC) ias-ra.c wolfssl-ra-attester.c wolfssl-ra.c ias_sign_ca_cert.c -l:libcurl.a -l:libwolfssl.a -l:libprotobuf-c.a -lm -l:libz.a

wolfssl/ldpreload.so: ldpreload.c
	$(CC) -o $@ $^ $(CFLAGSERRORS) $(SSL_SERVER_INCLUDES) -shared -fPIC -Lwolfssl -Ldeps/local/lib -l:libnonsdk-ra-attester.a -l:libcurl-openssl.a -l:libwolfssl.a -l:libssl.a -l:libcrypto.a -l:libprotobuf-c.a -l:libm.a -l:libz.a -ldl

mbedtls/ldpreload.so: ldpreload.c
	$(CC) -o $@ $^ $(CFLAGSERRORS) $(SSL_SERVER_INCLUDES) -shared -fPIC -Lmbedtls -Ldeps/local/lib -l:libnonsdk-ra-attester.a -l:libcurl-openssl.a -l:libmbedx509.a -l:libmbedtls.a -l:libmbedcrypto.a -l:libssl.a -l:libcrypto.a -l:libprotobuf-c.a -lm -l:libz.a -ldl

# xxd produces a header file. When included in multiple .c files it
# leads to "multiple definition errors". Produce a .h and .c file
# to avoid this.
ecdsa-sample-data/real/sample_data.c: ecdsa-sample-data/real/*.pem
	$(RM) $@
	for f in ecdsa-sample-data/real/*.pem ; do \
		xxd -i $$f >> $@ ; \
	done

ecdsa-sample-data/real/sample_data.h: ecdsa-sample-data/real/sample_data.c
	cat $^ | sed 's/ = .*;/;/' | sed '/^  /d' | sed 's/ = {/;/' | sed '/^};$$/d' | sed 's/^/extern /' > $@

ecdsa_sample_data.h:
	xxd -i ecdsa-sample-data/pckCert.pem >> $@
	xxd -i ecdsa-sample-data/pckcert-rsa2048.pem >> $@
	xxd -i ecdsa-sample-data/pckSignChain.pem >> $@
	xxd -i ecdsa-sample-data/quote-ppid-clear.dat >> $@
	xxd -i ecdsa-sample-data/quote-ppid-rsa3072.dat >> $@
	xxd -i ecdsa-sample-data/tcbInfo.json >> $@
	xxd -i ecdsa-sample-data/tcbSignChain.pem >> $@
	xxd -i ecdsa-sample-data/trustedRootCaCert.pem >> $@

clean:
	$(RM) ias-ra-openssl.c ias-ra-wolfssl.c
	$(RM) *.o
	$(RM) $(LIBS)
	$(RM) ecdsa-sample-data/real/sample_data.h
	$(RM) ecdsa-attestation-collateral.c ecdsa-attestation-collateral.h

mrproper: clean
	$(MAKE) -f ratls-wolfssl.mk mrproper
	$(RM) $(EXECS) $(LIBS)
	$(RM) -rf deps
	$(RM) -r openssl-ra-challenger wolfssl-ra-challenger mbedtls-ra-challenger openssl-ra-attester wolfssl-ra-attester mbedtls-ra-attester
	$(RM) messages.pb-c.h messages.pb-c.c ecdsa-aesmd-messages.pb-c.c ecdsa-aesmd-messages.pb-c.h ra_tls_options.c
	$(MAKE) -C sgxlkl distclean

.PHONY = all clean clients scone-server scone-wolfssl-ssl-server graphene-server sgxsdk-server mrproper

openssl-ra-attester: tests/ra-attester.c openssl/libnonsdk-ra-attester.a ra_tls_options.c 
	$(CC) $(CFLAGS) $(LDFLAGS_GRAPHENE_QUIRKS) $^ -o $@ -Ideps/local/include -Ldeps/local/lib -l:libcurl-openssl.a -l:libssl.a -l:libcrypto.a -l:libprotobuf-c.a -lm -l:libz.a -ldl
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal deps/graphene/Runtime/libpal-Linux-SGX.so -key deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -exec $@ -manifest ra-attester.manifest
ifndef ECDSA
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig
endif

wolfssl-ra-attester: tests/ra-attester.c wolfssl/libnonsdk-ra-attester.a ra_tls_options.c
	$(CC) $(CFLAGS) $(LDFLAGS_GRAPHENE_QUIRKS) $^ -o $@ -Ideps/local/include -Ldeps/local/lib -l:libcurl-wolfssl.a -l:libprotobuf-c.a -l:libwolfssl.a -lm -l:libz.a -ldl
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal deps/graphene/Runtime/libpal-Linux-SGX.so -key deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -exec $@ -manifest ra-attester.manifest
ifndef ECDSA
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig
endif

mbedtls-ra-attester: tests/ra-attester.c mbedtls/libnonsdk-ra-attester.a ra_tls_options.c 
	$(CC) $(CFLAGS) $(LDFLAGS_GRAPHENE_QUIRKS) $^ -o $@ -Ideps/local/include -Ldeps/local/lib -l:libcurl-mbedtls.a -l:libprotobuf-c.a -l:libmbedx509.a -l:libmbedtls.a -l:libmbedcrypto.a -l:libz.a
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal deps/graphene/Runtime/libpal-Linux-SGX.so -key deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -exec $@ -manifest ra-attester.manifest
ifndef ECDSA
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig
endif

openssl-ra-challenger: tests/ra-challenger.c openssl/libra-challenger.a
	$(CC) $(CFLAGS) -DOPENSSL $^ -o $@ -Ldeps/local/lib -l:libcrypto.a -ldl

WOLFSSL_RA_CHALLENGER_LIBS=-l:libwolfssl.a -lm
ifdef ECDSA
WOLFSSL_RA_CHALLENGER_LIBS+=-l:libQuoteVerification.so -ldl
wolfssl-ra-challenger: deps/local/lib/libQuoteVerification.so
endif

wolfssl-ra-challenger: tests/ra-challenger.c wolfssl/libra-challenger.a
	$(CC) $(CFLAGS) $(filter %.c %.a, $^) -o $@ -Ldeps/local/lib $(WOLFSSL_RA_CHALLENGER_LIBS)

mbedtls-ra-challenger: tests/ra-challenger.c mbedtls/libra-challenger.a
	$(CC) $(CFLAGS) $^ -o $@ -Ldeps/local/lib -l:libmbedx509.a -l:libmbedcrypto.a -lm

.PHONY: deps
deps: deps/linux-sgx deps/local/lib/libcurl-openssl.a deps/local/lib/libcurl-wolfssl.a deps/local/lib/libcurl-mbedtls.a deps/local/lib/libz.a deps/local/lib/libprotobuf-c.a
ifndef ECDSA
deps: deps/local/lib/libwolfssl.sgx.static.lib.a
endif

deps/openssl/config:
	cd deps && git clone https://github.com/openssl/openssl.git
	cd deps/openssl && git checkout OpenSSL_1_0_2g
	cd deps/openssl && ./config --prefix=$(shell readlink -f deps/local) no-shared -fPIC

deps/local/lib/libcrypto.a: deps/openssl/config
	cd deps/openssl && $(MAKE) && $(MAKE) -j1 install

deps/wolfssl/configure:
	cd deps && git clone https://github.com/wolfSSL/wolfssl
	cd deps/wolfssl && git checkout 57e5648a5dd734d1c219d385705498ad12941dd0
	cd deps/wolfssl && patch -p1 < ../../wolfssl.patch
	cd deps/wolfssl && ./autogen.sh

# Add --enable-debug to ./configure for debug build
# WOLFSSL_ALWAYS_VERIFY_CB ... Always call certificate verification callback, even if verification succeeds
# KEEP_OUR_CERT ... Keep the certificate around after the handshake
# --enable-tlsv10 ... required by libcurl
# 2019-03-19 removed --enable-intelasm configure flag. The Celeron NUC I am developing this, does not support AVX.
WOLFSSL_CFLAGS+=-DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_ALWAYS_VERIFY_CB -DKEEP_PEER_CERT
WOLFSSL_CONFIGURE_FLAGS+=--prefix=$(shell readlink -f deps/local) --enable-writedup --enable-static --enable-keygen --enable-certgen --enable-certext --with-pic --disable-examples --disable-crypttests --enable-aesni --enable-tlsv10
ifdef DEBUG
WOLFSS_CFLAGS+=--enable-debug
endif

deps/local/lib/libwolfssl.a: CFLAGS+= $(WOLFSSL_CFLAGS)
deps/local/lib/libwolfssl.a: deps/wolfssl/configure
# Force the use of gcc-5. Later versions of gcc report errors on this version of wolfSSL.
# TODO: Upgrade to more recent version of wolfSSL.
	cd deps/wolfssl && CC=gcc-5 CFLAGS="$(CFLAGS)" ./configure $(WOLFSSL_CONFIGURE_FLAGS)
	cd deps/wolfssl && $(MAKE) install

# Ideally, deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a and
# deps/local/lib/libwolfssl.a could be built in parallel. Does not
# work however. Hence, the dependency forces a serial build.
#
# -DFP_MAX_BITS=8192 required for RSA keys > 2048 bits to work
deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a: deps/local/lib/libwolfssl.a
	cd deps/wolfssl/IDE/LINUX-SGX && make -f sgx_t_static.mk CFLAGS="-DUSER_TIME -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_KEY_GEN -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT -DFP_MAX_BITS=8192"

deps/local/lib/libwolfssl.sgx.static.lib.a: deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a
	mkdir -p deps/local/lib && cp deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a deps/local/lib

deps/local/lib/libwolfssl.sgx.static.lib.a: deps/local/lib/libwolfssl.a

## mbedtls

ifndef DEBUG
MBEDTLS_RELEASE_TYPE=Release
else
MBEDTLS_RELEASE_TYPE=Debug
endif

deps/mbedtls/CMakeLists.txt:
	cd deps && git clone https://github.com/ARMmbed/mbedtls.git
	cd deps/mbedtls && git checkout mbedtls-2.5.1
	# Add  -DCMAKE_BUILD_TYPE=Debug for Debug
	cd deps/mbedtls && patch -p1 < ../../mbedtls-enlarge-cert-write-buffer.patch
	cd deps/mbedtls && patch -p1 < ../../mbedtls-ssl-server.patch
	cd deps/mbedtls && patch -p1 < ../../mbedtls-client.patch
	cd deps/mbedtls && cmake -DCMAKE_BUILD_TYPE=$(MBEDTLS_RELEASE_TYPE) -DENABLE_PROGRAMS=off -DCMAKE_C_COMPILER=$(CC) -DCMAKE_C_FLAGS="-fPIC -DMBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION" .

deps/local/lib/libmbedtls.a: deps/mbedtls/CMakeLists.txt
	$(MAKE) -C deps/mbedtls
	cd deps/mbedtls && cmake -D CMAKE_INSTALL_PREFIX=$(shell readlink -f deps/local) -P cmake_install.cmake

.PHONY: mrproper-mbedtls
mrproper-mbedtls:
	$(RM) -rf deps/mbedtls deps/local/lib/libmbedtls.a deps/local/lib/libmbedcrypto.a deps/local/lib/libmbedx509.a

deps/curl/configure:
	cd deps && git clone https://github.com/curl/curl.git
	cd deps/curl && git checkout curl-7_47_0
	cd deps/curl && ./buildconf

CURL_CONFFLAGS=--prefix=$(shell readlink -f deps/local) --without-libidn --without-librtmp --without-libssh2 --without-libmetalink --without-libpsl --disable-ldap --disable-ldaps --disable-shared
ifdef DEBUG
CURL_CONFFLAGS+=--enable-debug
endif

deps/local/lib/libcurl-wolfssl.a: deps/curl/configure deps/local/lib/libwolfssl.a
	cp -a deps/curl deps/curl-wolfssl
	cd deps/curl-wolfssl && CFLAGS="-fPIC" ./configure $(CURL_CONFFLAGS) --without-ssl --with-cyassl=$(shell readlink -f deps/local)
	cd deps/curl-wolfssl && $(MAKE)
	cp deps/curl-wolfssl/lib/.libs/libcurl.a deps/local/lib/libcurl-wolfssl.a

deps/local/lib/libcurl-openssl.a: deps/curl/configure deps/local/lib/libcrypto.a
	cp -a deps/curl deps/curl-openssl
	cd deps/curl-openssl && CFLAGS="-fPIC" LIBS="-ldl -lpthread" ./configure $(CURL_CONFFLAGS) --with-ssl=$(shell readlink -f deps/local)
	cd deps/curl-openssl && $(MAKE) && $(MAKE) install
	rename 's/libcurl/libcurl-openssl/' deps/local/lib/libcurl.*

deps/local/lib/libcurl-mbedtls.a: deps/curl/configure deps/local/lib/libmbedtls.a
	cp -a deps/curl deps/curl-mbedtls
	cd deps/curl-mbedtls && CFLAGS="-fPIC" LIBS="" ./configure $(CURL_CONFFLAGS) --without-ssl --with-mbedtls=$(shell readlink -f deps/local)
	cd deps/curl-mbedtls && $(MAKE) && $(MAKE) install
	rename 's/libcurl/libcurl-mbedtls/' deps/local/lib/libcurl.*

deps/zlib/configure:
	cd deps && git clone https://github.com/madler/zlib.git

deps/local/lib/libz.a: deps/zlib/configure
	mkdir -p deps
	cd deps/zlib && CFLAGS="-fPIC -O2" ./configure --prefix=$(shell readlink -f deps/local) --static
	cd deps/zlib && $(MAKE) install

deps/protobuf-c/configure:
	cd deps && git clone https://github.com/protobuf-c/protobuf-c.git
	cd deps/protobuf-c && ./autogen.sh

deps/local/lib/libprotobuf-c.a: deps/protobuf-c/configure
	cd deps/protobuf-c && CFLAGS="-fPIC -O2" ./configure --prefix=$(shell readlink -f deps/local) --disable-shared
	cd deps/protobuf-c && $(MAKE) protobuf-c/libprotobuf-c.la
	mkdir -p deps/local/lib && mkdir -p deps/local/include/protobuf-c
	cp deps/protobuf-c/protobuf-c/.libs/libprotobuf-c.a deps/local/lib
	cp deps/protobuf-c/protobuf-c/protobuf-c.h deps/local/include/protobuf-c

SGX_SDK_COMMIT=sgx_2.4
deps/linux-sgx:
	cd deps && git clone https://github.com/01org/linux-sgx.git
	cd $@ && git checkout $(SGX_SDK_COMMIT)

deps/SGXDataCenterAttestationPrimitives:
ifdef ECDSA
	cd deps && git clone $(SGX_DCAP_URI)
	cd $@ && git checkout $(SGX_DCAP_COMMIT)
	cd $@ && patch -p1 < ../../00_SGXDataCenterAttestationPrimitives.patch
else
	mkdir -p $@
endif

# This matches https://download.01.org/intel-sgx/linux-2.4/ubuntu16.04-server/
SGX_DRIVER_COMMIT=778dd1f711359cdabe4e1ca8d6cc5e5459474770
deps/linux-sgx-driver: deps/SGXDataCenterAttestationPrimitives
ifndef ECDSA
	cd deps && git clone https://github.com/01org/linux-sgx-driver.git
	cd $@ && git checkout $(SGX_DRIVER_COMMIT)
else
	cp -a $(SGX_DCAP)/driver/linux deps/linux-sgx-driver
endif

deps/local/lib/libQuoteVerification.so: deps/SGXDataCenterAttestationPrimitives
ifdef DEBUG
	cd deps/SGXDataCenterAttestationPrimitives/QuoteVerification/Src && ./debug
	cp deps/SGXDataCenterAttestationPrimitives/QuoteVerification/Src/Build/Debug/out/lib/libQuoteVerification.so $@
else
	cd deps/SGXDataCenterAttestationPrimitives/QuoteVerification/Src && ./release
	cp deps/SGXDataCenterAttestationPrimitives/QuoteVerification/Src/Build/Release/out/lib/libQuoteVerification.so $@
endif

ifdef ECDSA
# TODO merge FLC changes into Graphene master.
GRAPHENE_COMMIT?=0bc6b460b8e516615658f682eeebc3e7af48f0a7
else
# Most recent Graphene commit at time of update.
GRAPHENE_COMMIT?=ff8457f54e149565c3d97251eedc0d3348bae4e7
endif
GRAPHENE_URI?=https://github.com/oscarlab/graphene.git

ifdef ECDSA
# Origin lives at https://github.com/thomasknauth/graphene-sgx-driver
GRAPHENE_DRIVER_COMMIT?=4d0dc8bd261567aa3b69170eeacca076cbe9799b
endif

deps/graphene/Makefile: deps/linux-sgx-driver
	cd deps && git clone $(GRAPHENE_URI)
	cd deps/graphene && git submodule update --init Pal/src/host/Linux-SGX/sgx-driver
ifdef ECDSA
# TODO upstream changes to graphene-sgx-driver
	cd deps/graphene/Pal/src/host/Linux-SGX/sgx-driver && git checkout $(GRAPHENE_DRIVER_COMMIT)
	cd deps/graphene/Pal/src/host/Linux-SGX/sgx-driver && patch -p1 < ../../../../../../../00-graphene-driver-dcap.patch
endif
# Use --force here because some directories moved into standalone
# repositories at some point.
	cd deps/graphene && git checkout --force $(GRAPHENE_COMMIT)
	cd deps/graphene && openssl genrsa -3 -out Pal/src/host/Linux-SGX/signer/enclave-key.pem 3072
ifdef ECDSA
	cd deps/graphene && patch -p1 < ../../00-graphene-flexible-launch-control.patch
endif

deps/graphene/Runtime/pal-Linux-SGX: deps/graphene/Makefile
# The link-intel-driver.py script generates the isgx_driver.h
# file. Invoking it manually prevents the Graphene SGX driver from
# being built automatically (which may be undesirable when running in
# a Docker container, for example.)
	cd deps/graphene/Pal/src/host/Linux-SGX/sgx-driver && ISGX_DRIVER_PATH="$(shell readlink -f deps/linux-sgx-driver)" ISGX_DRIVER_VERSION=2.4 ./link-intel-driver.py
# Unfortunately, cannot use make -j`nproc` with Graphene's build process :(
	cd deps/graphene && $(MAKE) -j1 SGX=1

# I prefer to have all dynamic libraries in one directory. This
# reduces the effort in the Graphene-SGX manifest file.
	cd deps/graphene && ln -s /usr/lib/x86_64-linux-gnu/libprotobuf-c.so.1 Runtime/
	cd deps/graphene && ln -s /usr/lib/libsgx_uae_service.so Runtime/
	cd deps/graphene && ln -s /usr/lib/x86_64-linux-gnu/libcrypto.so Runtime/libcrypto.so.1.0.0
	cd deps/graphene && ln -s /lib/x86_64-linux-gnu/libz.so.1 Runtime/
	cd deps/graphene && ln -s /usr/lib/x86_64-linux-gnu/libssl.so Runtime/libssl.so.1.0.0

ecdsa-attestation-collateral.c:
	curl -o qe-identity.json "https://api.trustedservices.intel.com/sgx/certification/v1/qe/identity"
	curl -o root-ca-crl.pem "https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl"
	curl -o pck-crl.pem "https://api.trustedservices.intel.com/sgx/certification/v1/pckcrl?ca=processor"
	xxd -i qe-identity.json > $@
	xxd -i root-ca-crl.pem >> $@
	xxd -i pck-crl.pem >> $@

ecdsa-attestation-collateral.h: ecdsa-attestation-collateral.c
	cat $^ | sed 's/ = .*;/;/' | sed '/^  /d' | sed 's/ = {/;/' | sed '/^};$$/d' | sed 's/^/extern /' > $@

.PHONY: docker-image
docker-image: Dockerfile
	docker build -t ratls -f $^ .

.PHONY: tests
ifndef ECDSA
tests: openssl-ra-attester mbedtls-ra-attester
endif
tests: openssl-ra-challenger wolfssl-ra-challenger mbedtls-ra-challenger wolfssl-ra-attester

EPID_TEST_SUITE=tests/00_sgxsdk_server_client.py \
	tests/00_graphene_server_client.py \
	tests/00_attester_challenger.py \
	tests/00_sgxlkl_server_client.py \
	tests/00_secrect_provisioning_example.py

.PHONY: check
check: tests
ifeq ($(ECDSA),1)
	python3 tests/regression.py tests/00_ecdsa_attester_challenger.py
else
	python3 tests/regression.py $(EPID_TEST_SUITE)
endif
