# Makefile to build non-SGX-SDK-based RA-TLS client and server
# programs.

CFLAGS=-std=gnu99 -I. -I/opt/intel/sgxsdk/include -Ideps/local/include -fPIC
CFLAGSERRORS=-Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow -Werror
CFLAGS+=$(CFLAGSERRORS) -g -O0 -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_CERT_EXT # -DDEBUG -DDYNAMIC_RSA
CFLAGS+=-DSGX_GROUP_OUT_OF_DATE
LDFLAGS=-Ldeps/local/lib -Lopenssl -static
LDLIBS=-l:libwolfssl.a -l:libm.a -l:libpthread.a -l:libmbedtls.a -l:libmbedx509.a -l:libmbedcrypto.a -lssl -lcrypto

EXECS=mbedtls-ssl-server \
	wolfssl-ssl-server \
	mbedtls-client \
	wolfssl-client \
	openssl-client \
  deps/wolfssl-examples/SGX_Linux/App

LIBS=libmbedtls-ra-attester.a \
	libwolfssl-ra-attester.a \
	libnonsdk-ra-attester.a \
	libmbedtls-ra-challenger.a \
	libwolfssl-ra-challenger.a 

all : $(EXECS) $(LIBS)

wolfssl-client : deps/wolfssl-examples/tls/client-tls.c libwolfssl-ra-challenger.a
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) $(LDLIBS)

mbedtls-client : deps/mbedtls/programs/ssl/ssl_client1.c libwolfssl-ra-challenger.a 
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) $(LDLIBS)

openssl-client : openssl-client.c openssl-ra-challenger.c ra-challenger.c
	$(CC) -o $@ $^ $(CFLAGS) -Ldeps/local/lib -lssl -lcrypto -lm

libmbedtls-ra-challenger.a : mbedtls-ra-challenger.o ra-challenger.o
	$(AR) rcs $@ $^

libwolfssl-ra-challenger.a : wolfssl-ra-challenger.o wolfssl-ra.o ra-challenger.o
	$(AR) rcs $@ $^

libmbedtls-ra-attester.a : mbedtls-ra-attester.o ias-ra.o
	$(AR) rcs $@ $^

libwolfssl-ra-attester.a : wolfssl-ra-attester.o ias-ra.o
	$(AR) rcs $@ $^

SGX_GIT=deps/linux-sgx
EPID_SDK=$(SGX_GIT)/external/epid-sdk-3.0.0

CFLAGS+=-I$(SGX_GIT)/common/inc/internal -I$(EPID_SDK) -I$(SGX_GIT)/common/inc

WOLFSSL_RA_ATTESTER_SRC=wolfssl-ra-attester.c wolfssl-ra.c
MBEDTLS_RA_ATTESTER_SRC=mbedtls-ra-attester.c ra-challenger.c
MBEDTLS_RA_CHALLENGER_SRC=mbedtls-ra-challenger.c
NONSDK_RA_ATTESTER_SRC=ias-ra.c nonsdk-ra-attester.c messages.pb-c.c sgx_report.S

messages.pb-c.c messages.pb-c.h :
	( cd deps/linux-sgx/psw/ae/common/proto/ ; protoc-c messages.proto --c_out=. )
	cp deps/linux-sgx/psw/ae/common/proto/messages.pb-c.c deps/linux-sgx/psw/ae/common/proto/messages.pb-c.h .

libnonsdk-ra-attester.a : mbedtls-ra-attester.o ias-ra.o nonsdk-ra-attester.o messages.pb-c.o sgx_report.o
		$(AR) rcs $@ $^


#### HTTPS server based on mbedtls and wolfSSL. Use with Graphene-SGX.

SSL_SERVER_INCLUDES=-I. -I/opt/intel/sgxsdk/include -Ideps/local/include \
	-Ideps/linux-sgx/common/inc/internal \
  -Ideps/linux-sgx/external/epid-sdk-3.0.0 \
  -I$(SGX_GIT)/common/inc

MBEDTLS_SSL_SERVER_SRC=deps/mbedtls/programs/ssl/ssl_server.c \
	ra_tls_options.c \
	$(MBEDTLS_RA_ATTESTER_SRC) $(MBEDTLS_RA_CHALLENGER_SRC) \
	$(NONSDK_RA_ATTESTER_SRC)
MBEDTLS_SSL_SERVER_LIBS=-l:libcurl.a -lcrypto -lprotobuf-c -lssl -l:libmbedx509.a -l:libmbedtls.a -l:libmbedcrypto.a -lz

mbedtls-ssl-server : $(MBEDTLS_SSL_SERVER_SRC) ssl-server.manifest
	$(CC) $(MBEDTLS_SSL_SERVER_SRC) -o $@ $(CFLAGSERRORS) $(SSL_SERVER_INCLUDES) -Ldeps/local/lib/ $(MBEDTLS_SSL_SERVER_LIBS)
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal deps/graphene/Runtime/libpal-Linux-SGX.so -key deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -exec $@ -manifest ssl-server.manifest
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig

WOLFSSL_SSL_SERVER_SRC=deps/wolfssl-examples/tls/server-tls.c \
	ra_tls_options.c \
	$(WOLFSSL_RA_ATTESTER_SRC) \
  $(NONSDK_RA_ATTESTER_SRC)

WOLFSSL_SSL_SERVER_LIBS=-l:libcurl.a -l:libwolfssl.a -lcrypto -lprotobuf-c -lssl -lm -lz

wolfssl-ssl-server : $(WOLFSSL_SSL_SERVER_SRC) ssl-server.manifest
	$(CC) -o $@ $(CFLAGSERRORS) $(SSL_SERVER_INCLUDES) -Ldeps/local/lib $(WOLFSSL_SSL_SERVER_SRC) $(WOLFSSL_SSL_SERVER_LIBS)
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal deps/graphene/Runtime/libpal-Linux-SGX.so -key deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -exec $@ -manifest ssl-server.manifest
	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig

deps/wolfssl-examples/SGX_Linux/App : deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a libsgx_ra_tls_wolfssl.a sgxsdk-ra-attester_u.c ias-ra.c
	cp sgxsdk-ra-attester_u.c ias-ra.c deps/wolfssl-examples/SGX_Linux/untrusted
	make -C deps/wolfssl-examples/SGX_Linux SGX_MODE=HW SGX_DEBUG=1 SGX_WOLFSSL_LIB=$(shell readlink -f deps/wolfssl/IDE/LINUX-SGX) SGX_SDK=/opt/intel/sgxsdk WOLFSSL_ROOT=$(shell readlink -f deps/wolfssl) SGX_RA_TLS_LIB=$(shell readlink -f .)

README.html : README.md
	pandoc --from markdown_github --to html --standalone $< --output $@

clean :
	$(RM) *.o

mrproper : clean
	$(RM) $(EXECS) $(LIBS)

.PHONY = all clean mrproper
