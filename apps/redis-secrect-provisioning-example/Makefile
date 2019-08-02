SGX_SDK?=/opt/intel/sgxsdk

CFLAGS+=-std=gnu99
CFLAGSERRORS=-Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow -Werror
CFLAGS+=$(CFLAGSERRORS)

GRAPHENEDIR=../../deps/graphene

CFLAGS+= \
  -I../../deps/local/include \
	-I$(SGX_SDK)/include \
  -I../../

ifeq ($(DEBUG),1)
CFLAGS+=-g -ggdb -O0
else
CFLAGS+=-O2
endif

verifier-crt.pem:
	openssl req -x509 -nodes -newkey rsa:3072 -keyout verifier-key.pem -out $@ -days 365 -subj '/CN=localhost'

LDLIBS=\
  ../../mbedtls/libra-challenger.a \
  ../../deps/local/lib/libmbedtls.a \
  ../../deps/local/lib/libmbedcrypto.a \
  ../../deps/local/lib/libmbedx509.a

redis_server_sgx_identity.c: redis-server.token
	MRSIGNER=`python -c 'print open("redis-server.token").read()[128:128+32]' | xxd -i`; \
	MRENCLAVE=`python -c 'print open("redis-server.sig").read()[960:960+32]' | xxd -i` ; \
	echo "const char redis_server_mrenclave[] = { $$MRENCLAVE };" > $@ ; \
	echo "const char redis_server_mrsigner[]  = { $$MRSIGNER };" >> $@

../../deps/local/lib/libmbedtls.a:
	cd ../.. && $(MAKE) deps/local/lib/libmbedtls.a

../../mbedtls/libra-challenger.a: ../../deps/local/lib/libmbedtls.a
	cd ../.. && $(MAKE) mbedtls/libra-challenger.a

verifier: ../../mbedtls/libra-challenger.a redis_server_sgx_identity.c

RATLS_GIT_URI?=https://github.com/cloud-security-research/sgx-ra-tls.git
RATLS_COMMIT?=master
../../Makefile:
	cd deps && git clone $(RATLS_GIT_URI)
	cd ../.. && git checkout $(RATLS_COMMIT)

redis/Makefile:
	wget https://github.com/antirez/redis/archive/5.0.0.zip -O redis-5.0.0.zip
	unzip redis-5.0.0.zip
	ln -s redis-5.0.0 redis

redis/src/redis-server: redis/Makefile
	cd redis && $(MAKE) noopt

%.token: %.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@ -sig $<

redis-server.sig: ../../deps/graphene/Runtime/redis-server-provision-secret.so verifier-crt.pem

redis-server.sig: redis/src/redis-server redis-server.manifest ../../deps/graphene/Runtime/pal-Linux-SGX
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so -key $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output redis-server.manifest.sgx -exec redis/src/redis-server -manifest redis-server.manifest


PROVISION_LDLIBS= \
  ../../mbedtls/libnonsdk-ra-attester.a \
  ../../deps/local/lib/libprotobuf-c.a \
  ../../deps/local/lib/libcurl-mbedtls.a \
  ../../deps/local/lib/libmbedtls.a \
  ../../deps/local/lib/libmbedcrypto.a \
  ../../deps/local/lib/libmbedx509.a

PROVISION_LDFLAGS=-shared

../../mbedtls/libnonsdk-ra-attester.a:
	cd ../.. && $(MAKE) deps/linux-sgx
	cd ../.. && $(MAKE) deps/local/lib/libprotobuf-c.a
	cd ../.. && $(MAKE) deps/local/lib/libcurl-mbedtls.a
	cd ../.. && $(MAKE) mbedtls/libnonsdk-ra-attester.a

redis-server-provision-secret.so: ../../mbedtls/libnonsdk-ra-attester.a redis-server-provision-secret.c | verifier-crt.pem
	$(CC) $(CFLAGS) -Iredis/src $^ -o $@ $(PROVISION_LDFLAGS) -fPIC $(PROVISION_LDLIBS)

../../deps/graphene/Runtime/pal-Linux-SGX: ../../Makefile
	cd ../.. && $(MAKE) deps/graphene/Runtime/pal-Linux-SGX

../../deps/graphene/Runtime/redis-server-provision-secret.so: redis-server-provision-secret.so | ../../deps/graphene/Runtime/pal-Linux-SGX
	cp $^ $@

.PHONY=redis-server-run
redis-server-run: ../../deps/graphene/Runtime/redis-server-provision-secret.so redis-server.token
	$(GRAPHENEDIR)/Runtime/pal-Linux-SGX ./redis-server.manifest.sgx --save "" --protected-mode no --requirepass XXXXX

.PHONY=redis-server-clean
redis-server-clean:
	$(RM) redis-server.token redis-server.sig redis-server.manifest.sgx ../../deps/graphene/Runtime/redis-server-provision-secret.so redis-server-provision-secret.so
	$(RM) redis_server_sgx_identity.c

.PHONY=mrproper
mrproper: redis-server-clean
	$(RM) -rf redis-5.0.0 redis redis-5.0.0.zip verifier redis-server-provision-secret.so verifier-crt.pem verifier-key.pem

%.html: %.md
	pandoc --from markdown_github --to html --standalone $< --output $@

html: README.html

.PHONY=verifier-run
verifier-run: verifier
ifeq ($(DEBUG),1)
	gdb --args ./verifier
else
	./verifier
endif
