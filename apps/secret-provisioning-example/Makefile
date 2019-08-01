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

.PHONY: default
default: secret-provisioning-service

secret-provisioning-service-crt.pem:
	openssl req -x509 -nodes -newkey rsa:3072 -keyout secret-provisioning-service-key.pem -out $@ -days 365 -subj '/CN=localhost'

LDLIBS=\
  ../../mbedtls/libra-challenger.a \
  ../../deps/local/lib/libmbedtls.a \
  ../../deps/local/lib/libmbedcrypto.a \
  ../../deps/local/lib/libmbedx509.a

# The $(subst -,_,$*) gymnastics turns - (dash) into _ (underscore)
# because - (dash) is not valid within a C variable name.
%_sgx_identity.c: %.token
	MRSIGNER=`python -c 'print open("$^").read()[128:128+32]' | xxd -i`; \
	MRENCLAVE=`python -c 'print open("$*.sig").read()[960:960+32]' | xxd -i` ; \
	echo "const char $(subst -,_,$*)_mrenclave[] = { $$MRENCLAVE };" > $@ ; \
	echo "const char $(subst -,_,$*)_mrsigner[]  = { $$MRSIGNER };" >> $@

../../deps/local/lib/libmbedtls.a:
	cd ../.. && $(MAKE) deps/local/lib/libmbedtls.a

../../mbedtls/libra-challenger.a: ../../deps/local/lib/libmbedtls.a
	cd ../.. && $(MAKE) mbedtls/libra-challenger.a

secret-provisioning-service: ../../mbedtls/libra-challenger.a redis-server_sgx_identity.c show-secrets_sgx_identity.c

RATLS_GIT_URI?=https://github.com/cloud-security-research/sgx-ra-tls.git
RATLS_COMMIT?=master
../../Makefile:
	cd deps && git clone $(RATLS_GIT_URI)
	cd ../.. && git checkout $(RATLS_COMMIT)

redis/Makefile:
	wget https://github.com/antirez/redis/archive/5.0.0.zip -O redis-5.0.0.zip
	unzip redis-5.0.0.zip
	ln -s redis-5.0.0 redis

# If REDIS_SERVER_BINARY is set, do not install from source.
ifneq ($(REDIS_SERVER_BINARY),)
redis/src/redis-server:
	mkdir -p redis/src
	ln -s $(REDIS_SERVER_BINARY) $@
else
redis/src/redis-server: redis/Makefile
	cd redis && $(MAKE) noopt
endif

%.token: %.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@ -sig $<

redis-server.sig: ../../deps/graphene/Runtime/redis-server-grab-secret.so secret-provisioning-service-crt.pem
redis-server.sig: redis/src/redis-server redis-server.manifest ../../deps/graphene/Runtime/pal-Linux-SGX
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so -key $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output redis-server.manifest.sgx -exec redis/src/redis-server -manifest redis-server.manifest

show-secrets.sig: show-secrets secret-provisioning-service-crt.pem ../../deps/graphene/Runtime/show-secrets-grab-secret.so show-secrets
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so -key $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $(basename $@).manifest.sgx -exec $(basename $@) -manifest $(basename $@).manifest

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

../../ra_tls_options.c:
	$(MAKE) -C $(dir $@) $(notdir $@)

redis-server-grab-secret.so: ../../mbedtls/libnonsdk-ra-attester.a redis-server-grab-secret.c ../../ra_tls_options.c | secret-provisioning-service-crt.pem
	$(CC) $(CFLAGS) -Iredis/src $^ -o $@ $(PROVISION_LDFLAGS) -fPIC $(PROVISION_LDLIBS)

../../deps/graphene/Runtime/pal-Linux-SGX: ../../Makefile
	cd ../.. && $(MAKE) deps/graphene/Runtime/pal-Linux-SGX

../../deps/graphene/Runtime/redis-server-grab-secret.so: redis-server-grab-secret.so | ../../deps/graphene/Runtime/pal-Linux-SGX
	cp $^ $@

.PHONY: redis-server-run
redis-server-run: redis-server.token
	$(GRAPHENEDIR)/Runtime/pal-Linux-SGX ./redis-server.manifest.sgx --save "" --protected-mode no --requirepass XXXXX

.PHONY: redis-server-clean
redis-server-clean:
	$(RM) redis-server.token redis-server.sig redis-server.manifest.sgx ../../deps/graphene/Runtime/redis-server-grab-secret.so redis-server-grab-secret.so
	$(RM) redis_server_sgx_identity.c

.PHONY: clean
clean: redis-server-clean show-secrets-clean
	$(RM) -rf secret-provisioning-service redis-server-grab-secret.so secret-provisioning-service-crt.pem secret-provisioning-service-key.pem

.PHONY: distclean
distclean: clean
	$(RM) -rf redis-5.0.0 redis redis-5.0.0.zip

show-secrets-grab-secret.so: show-secrets-grab-secret.c ../../ra_tls_options.c
	$(CC) $(CFLAGS) $(PROVISION_LDFLAGS) $^ -o $@ $(PROVISION_LDLIBS) -fPIC

../../deps/graphene/Runtime/show-secrets-grab-secret.so: show-secrets-grab-secret.so | ../../deps/graphene/Runtime/pal-Linux-SGX
	cp $^ $@

.PHONY: show-secrets-run
show-secrets-run: show-secrets.token
	SECRET=not-the-real-thing $(GRAPHENEDIR)/Runtime/pal-Linux-SGX ./show-secrets.manifest.sgx --requirepass XxxXXxxXX

.PHONY: show-secrets-clean
show-secrets-clean:
	$(RM) -rf show-secrets show-secrets-grab-secret.so ../../deps/graphene/Runtime/show-secrets-grab-secret.so show-secrets.token show-secrets.sig show-secrets.manifest.sgx show-secrets_sgx_identity.c

%.html: %.md
	pandoc --from markdown_github --to html --standalone $< --output $@

html: README.html

.PHONY: secret-provisioning-service-run
secret-provisioning-service-run: secret-provisioning-service
ifeq ($(DEBUG),1)
	gdb --args ./secret-provisioning-service
else
	./secret-provisioning-service
endif

.PHONY: check
check: secret-provisioning-service
	cd ../.. && python3 tests/00_secrect_provisioning_example.py
