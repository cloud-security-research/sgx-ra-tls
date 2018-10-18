# Makefile to build non-SGX-SDK-based RA-TLS client and server
# programs.

# TODO: We must use Curl with OpenSSL (see https://github.com/cloud-security-research/sgx-ra-tls/issues/1). We are stuck with two libs for now.

export SGX_SDK?=/opt/intel/sgxsdk
CFLAGS=-std=gnu99 -I. -I$(SGX_SDK)/include -Ideps/local/include -fPIC
CFLAGSERRORS=-Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow -Werror
CFLAGS+=$(CFLAGSERRORS) -g -O0 -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_CERT_EXT # -DDEBUG -DDYNAMIC_RSA
CFLAGS+=-DSGX_GROUP_OUT_OF_DATE

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

.PHONY=all
all: $(LIBS)

wolfssl-client : deps/wolfssl-examples/tls/client-tls.c wolfssl/libra-challenger.a
	$(CC) -o $@ $(filter %.c, $^) $(CFLAGS) -Lwolfssl -Ldeps/local/lib -l:libra-challenger.a -l:libwolfssl.a -lm

wolfssl-client-mutual: deps/wolfssl-examples/tls/client-tls.c ra_tls_options.c wolfssl/libra-challenger.a wolfssl/libnonsdk-ra-attester.a
	$(CC) -o $@ $(filter %.c, $^) $(CFLAGS) -DSGX_RATLS_MUTUAL -Ldeps/local/lib $(filter %.a, $^) $(WOLFSSL_SSL_SERVER_LIBS)
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal deps/graphene/Runtime/libpal-Linux-SGX.so -key deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -exec $@ -manifest ssl-server.manifest
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig

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

mbedtls/libra-challenger.a : mbedtls mbedtls-ra-challenger.o ra-challenger.o ias_sign_ca_cert.o
	$(AR) rcs $@ $(filter %.o, $^)

mbedtls/libra-attester.a : mbedtls mbedtls-ra-attester.o ias-ra-openssl.o
	$(AR) rcs $@ $(filter %.o, $^)

mbedtls/libnonsdk-ra-attester.a : mbedtls mbedtls-ra-attester.o ias-ra-openssl.o nonsdk-ra-attester.o messages.pb-c.o sgx_report.o
	$(AR) rcs $@ $(filter %.o, $^)

nonsdk-ra-attester.o: messages.pb-c.h

mbedtls/libra-tls.so : mbedtls mbedtls-ra-challenger.o ra-challenger.o ias_sign_ca_cert.o mbedtls-ra-attester.o ias-ra-openssl.o nonsdk-ra-attester.o messages.pb-c.o sgx_report.o
	$(CC) -shared -o $@ $(filter %.o, $^) -Ldeps/local/lib -l:libcurl-openssl.a -l:libmbedtls.a -l:libmbedx509.a -l:libmbedcrypto.a -l:libprotobuf-c.a -l:libz.a -l:libssl.a -l:libcrypto.a -ldl

wolfssl/libra-challenger.a : wolfssl wolfssl-ra-challenger.o wolfssl-ra.o ra-challenger.o ias_sign_ca_cert.o
	$(AR) rcs $@ $(filter %.o, $^)

ias-ra-%.c: ias-ra.c
	cp $< $@

ias-ra-wolfssl.o: CFLAGS += -DUSE_WOLFSSL

wolfssl/libra-attester.a: wolfssl wolfssl-ra-attester.o wolfssl-ra.o ias-ra-wolfssl.o
	$(AR) rcs $@ $(filter %.o, $^)

wolfssl/libnonsdk-ra-attester.a : wolfssl wolfssl-ra.o wolfssl-ra-attester.o ias-ra-wolfssl.o nonsdk-ra-attester.o messages.pb-c.o sgx_report.o
		$(AR) rcs $@ $(filter %.o, $^)

wolfssl/libra-tls.so : wolfssl wolfssl-ra-challenger.o wolfssl-ra.o ra-challenger.o ias_sign_ca_cert.o wolfssl-ra-attester.o ias-ra-wolfssl.o nonsdk-ra-attester.o messages.pb-c.o sgx_report.o
	$(CC) -shared -o $@ $(filter %.o, $^) -Ldeps/local/lib -l:libcurl-wolfssl.a -l:libwolfssl.a -l:libprotobuf-c.a -l:libz.a -l:libssl.a -l:libcrypto.a -ldl

openssl/libra-challenger.a : openssl ra-challenger.o openssl-ra-challenger.o ias_sign_ca_cert.o
	$(AR) rcs $@ $(filter %.o, $^)

openssl/libnonsdk-ra-attester.a : openssl ra-challenger.o openssl-ra-attester.o ias-ra-openssl.o  nonsdk-ra-attester.o messages.pb-c.o sgx_report.o
	$(AR) rcs $@ $(filter %.o, $^)

SGX_GIT=deps/linux-sgx
EPID_SDK=$(SGX_GIT)/external/epid-sdk-3.0.0

CFLAGS+=-I$(SGX_GIT)/common/inc/internal -I$(EPID_SDK) -I$(SGX_GIT)/common/inc

WOLFSSL_RA_ATTESTER_SRC=wolfssl-ra-attester.c wolfssl-ra.c
MBEDTLS_RA_ATTESTER_SRC=mbedtls-ra-attester.c ra-challenger.c
MBEDTLS_RA_CHALLENGER_SRC=mbedtls-ra-challenger.c ias_sign_ca_cert.c
NONSDK_RA_ATTESTER_SRC=ias-ra.c nonsdk-ra-attester.c messages.pb-c.c sgx_report.S

messages.pb-c.c messages.pb-c.h :
	( cd deps/linux-sgx/psw/ae/common/proto/ ; protoc-c messages.proto --c_out=. )
	cp deps/linux-sgx/psw/ae/common/proto/messages.pb-c.c deps/linux-sgx/psw/ae/common/proto/messages.pb-c.h .

#### HTTPS server based on mbedtls and wolfSSL. Use with Graphene-SGX.

SSL_SERVER_INCLUDES=-I. -I$(SGX_SDK)/include -Ideps/local/include \
	-Ideps/linux-sgx/common/inc/internal \
  -Ideps/linux-sgx/external/epid-sdk-3.0.0 \
  -I$(SGX_GIT)/common/inc

MBEDTLS_SSL_SERVER_SRC=deps/mbedtls/programs/ssl/ssl_server.c \
	ra_tls_options.c \
	$(MBEDTLS_RA_ATTESTER_SRC) $(MBEDTLS_RA_CHALLENGER_SRC) \
	$(NONSDK_RA_ATTESTER_SRC)
MBEDTLS_SSL_SERVER_LIBS=-l:libcurl-openssl.a -l:libmbedx509.a -l:libmbedtls.a -l:libmbedcrypto.a -l:libprotobuf-c.a -l:libz.a -l:libssl.a -l:libcrypto.a -ldl

mbedtls-ssl-server : $(MBEDTLS_SSL_SERVER_SRC) ssl-server.manifest deps/graphene/Runtime/pal_loader
	$(CC) $(MBEDTLS_SSL_SERVER_SRC) -o $@ $(CFLAGSERRORS) $(SSL_SERVER_INCLUDES) -Ldeps/local/lib/ $(MBEDTLS_SSL_SERVER_LIBS)
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal deps/graphene/Runtime/libpal-Linux-SGX.so -key deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -exec $@ -manifest ssl-server.manifest
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig

WOLFSSL_SSL_SERVER_SRC=deps/wolfssl-examples/tls/server-tls.c ra_tls_options.c

WOLFSSL_SSL_SERVER_LIBS=-l:libcurl-wolfssl.a -l:libwolfssl.a -l:libprotobuf-c.a -l:libz.a -lm -ldl

wolfssl-ssl-server: $(WOLFSSL_SSL_SERVER_SRC) ssl-server.manifest deps/graphene/Runtime/pal_loader wolfssl/libnonsdk-ra-attester.a
	$(CC) -o $@ $(CFLAGSERRORS) $(SSL_SERVER_INCLUDES) -Ldeps/local/lib -L. -Lwolfssl $(WOLFSSL_SSL_SERVER_SRC) -l:libnonsdk-ra-attester.a $(WOLFSSL_SSL_SERVER_LIBS)
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal deps/graphene/Runtime/libpal-Linux-SGX.so -key deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -exec $@ -manifest ssl-server.manifest
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig

wolfssl-ssl-server-mutual: deps/wolfssl-examples/tls/server-tls.c ra_tls_options.c ssl-server.manifest deps/graphene/Runtime/pal_loader wolfssl/libra-challenger.a wolfssl/libnonsdk-ra-attester.a
	$(CC) -o $@ $(CFLAGSERRORS) -DSGX_RATLS_MUTUAL $(SSL_SERVER_INCLUDES) $(filter %.c, $^) -Ldeps/local/lib wolfssl/libra-challenger.a wolfssl/libnonsdk-ra-attester.a $(WOLFSSL_SSL_SERVER_LIBS)
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal deps/graphene/Runtime/libpal-Linux-SGX.so -key deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -exec $@ -manifest ssl-server.manifest
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig

libsgx_ra_tls_wolfssl.a:
	make -f ratls-wolfssl.mk
	rm -f wolfssl-ra-challenger.o wolfssl-ra.o ra-challenger.o ias_sign_ca_cert.o  # BUGFIX: previous Makefile compiles these .o files with incorrect C flags

deps/wolfssl-examples/SGX_Linux/App: deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a libsgx_ra_tls_wolfssl.a sgxsdk-ra-attester_u.c ias-ra.c
	cp sgxsdk-ra-attester_u.c ias-ra.c deps/wolfssl-examples/SGX_Linux/untrusted
	$(MAKE) -C deps/wolfssl-examples/SGX_Linux SGX_MODE=HW SGX_DEBUG=1 SGX_WOLFSSL_LIB=$(shell readlink -f deps/wolfssl/IDE/LINUX-SGX) SGX_SDK=$(SGX_SDK) WOLFSSL_ROOT=$(shell readlink -f deps/wolfssl) SGX_RA_TLS_LIB=$(shell readlink -f .)

README.html : README.md
	pandoc --from markdown_github --to html --standalone $< --output $@

SCONE_SSL_SERVER_INCLUDES=-I. -I$(SGX_SDK)/include -ISCONE/deps/local/include \
	-Ideps/linux-sgx/common/inc/internal \
  -Ideps/linux-sgx/external/epid-sdk-3.0.0 \
  -I$(SGX_GIT)/common/inc

SGXLKL_SSL_SERVER_INCLUDES=-I. -I$(SGX_SDK)/include \
  -Isgxlkl/local/include \
	-Ideps/linux-sgx/common/inc/internal \
  -Ideps/linux-sgx/external/epid-sdk-3.0.0 \
  -I$(SGX_GIT)/common/inc

clients: mbedtls-client wolfssl-client openssl-client
graphene-server: wolfssl-ssl-server mbedtls-ssl-server wolfssl-ssl-server-mutual
scone-server: scone-wolfssl-ssl-server
sgxsdk-server: deps/wolfssl-examples/SGX_Linux/App

scone-wolfssl-ssl-server: $(WOLFSSL_SSL_SERVER_SRC)
	/usr/local/bin/scone-gcc -o $@ $(CFLAGSERRORS) $(SCONE_SSL_SERVER_INCLUDES) -LSCONE/deps/local/lib $(WOLFSSL_SSL_SERVER_SRC) $(WOLFSSL_SSL_SERVER_LIBS)

# SGX-LKL requires position independent code (flags: -fPIE -pie) to
# map the binary anywhere in the address space.
sgxlkl-wolfssl-ssl-server: $(WOLFSSL_SSL_SERVER_SRC)
	sgxlkl/sgx-lkl/build/host-musl/bin/musl-gcc -o $@ -fPIE -pie $(CFLAGSERRORS) $(SGXLKL_SSL_SERVER_INCLUDES) -Lsgxlkl/local/lib $(WOLFSSL_SSL_SERVER_SRC) wolfssl-ra-challenger.c ra-challenger.c ias_sign_ca_cert.c -l:libcurl.a -l:libwolfssl.a -l:libssl.a -l:libcrypto.a -l:libprotobuf-c.a -lm -l:libz.a

wolfssl/ldpreload.so: ldpreload.c
	$(CC) -o $@ $^ $(CFLAGSERRORS) $(SSL_SERVER_INCLUDES) -shared -fPIC -Lwolfssl -Ldeps/local/lib -l:libnonsdk-ra-attester.a -l:libcurl-openssl.a -l:libwolfssl.a -l:libssl.a -l:libcrypto.a -l:libprotobuf-c.a -l:libm.a -l:libz.a -ldl

mbedtls/ldpreload.so: ldpreload.c
	$(CC) -o $@ $^ $(CFLAGSERRORS) $(SSL_SERVER_INCLUDES) -shared -fPIC -Lmbedtls -Ldeps/local/lib -l:libnonsdk-ra-attester.a -l:libcurl-openssl.a -l:libmbedx509.a -l:libmbedtls.a -l:libmbedcrypto.a -l:libssl.a -l:libcrypto.a -l:libprotobuf-c.a -lm -l:libz.a -ldl

clean:
	$(RM) *.o

mrproper: clean
	$(MAKE) -f ratls-wolfssl.mk mrproper
	$(RM) $(EXECS) $(LIBS)
	$(RM) -rf deps
	$(RM) -r openssl-ra-challenger wolfssl-ra-challenger mbedtls-ra-challenger openssl-ra-attester wolfssl-ra-attester mbedtls-ra-attester
	$(RM) messages.pb-c.h messages.pb-c.c

.PHONY = all clean clients scone-server scone-wolfssl-ssl-server graphene-server sgxsdk-server mrproper

openssl-ra-attester: tests/ra-attester.c openssl/libnonsdk-ra-attester.a ra_tls_options.c 
	$(CC) $(CFLAGS) $^ -o $@ -Ideps/local/include -Ldeps/local/lib -l:libcurl-openssl.a -l:libssl.a -l:libcrypto.a -l:libprotobuf-c.a -lm -l:libz.a -ldl
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal deps/graphene/Runtime/libpal-Linux-SGX.so -key deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -exec $@ -manifest ssl-server.manifest
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig

wolfssl-ra-attester: tests/ra-attester.c wolfssl/libnonsdk-ra-attester.a ra_tls_options.c 
	$(CC) $(CFLAGS) $^ -o $@ -Ideps/local/include -Ldeps/local/lib -l:libcurl-wolfssl.a -l:libprotobuf-c.a -l:libwolfssl.a -lm -l:libz.a -ldl
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal deps/graphene/Runtime/libpal-Linux-SGX.so -key deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -exec $@ -manifest ssl-server.manifest
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig

mbedtls-ra-attester: tests/ra-attester.c mbedtls/libnonsdk-ra-attester.a ra_tls_options.c 
	$(CC) $(CFLAGS) $^ -o $@ -Ideps/local/include -Ldeps/local/lib -l:libcurl-openssl.a -l:libssl.a -l:libcrypto.a -l:libprotobuf-c.a -l:libmbedx509.a -l:libmbedtls.a -l:libmbedcrypto.a -lm -l:libz.a -ldl
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal deps/graphene/Runtime/libpal-Linux-SGX.so -key deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -exec $@ -manifest ssl-server.manifest
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig

openssl-ra-challenger: tests/ra-challenger.c openssl/libra-challenger.a
	$(CC) $(CFLAGS) -DOPENSSL $^ -o $@ -l:libcrypto.a -ldl

wolfssl-ra-challenger: tests/ra-challenger.c wolfssl/libra-challenger.a
	$(CC) $(CFLAGS) $^ -o $@ -Ldeps/local/lib -l:libwolfssl.a -lm

mbedtls-ra-challenger: tests/ra-challenger.c mbedtls/libra-challenger.a
	$(CC) $(CFLAGS) $^ -o $@ -Ldeps/local/lib -l:libmbedx509.a -l:libmbedcrypto.a -lm

.PHONY=tests
tests: openssl-ra-challenger wolfssl-ra-challenger mbedtls-ra-challenger openssl-ra-attester wolfssl-ra-attester mbedtls-ra-attester
