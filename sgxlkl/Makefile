.PHONY: all
all:
	$(MAKE) sgx-lkl/apps/ratls/sgxlkl-miniroot-fs.img
	$(MAKE) sgx-lkl/apps/https-server/sgxlkl-miniroot-fs.img

.PHONY: sgx-lkl
sgx-lkl:
	[ ! -d $@ ] && git clone https://github.com/lsds/sgx-lkl.git || true
	cd sgx-lkl && git checkout 2c0aa8a41178637ac8f4dabd8f7f02a5b47eed90
	cd sgx-lkl && $(MAKE) -j1
	cd sgx-lkl && $(MAKE) -j1 sgx-lkl-sign

SRC=../wolfssl-ra-attester.c \
	../wolfssl-ra.c \
	../ias_sign_ca_cert.c \
	../ias-ra.c \
	../nonsdk-ra-attester.c \
	../messages.pb-c.c \
	../sgx_report.S \
	../ra_tls_options.c

INCLUDES=-I.. -Ilocal/include -I/opt/intel/sgxsdk/include \
  -I../deps/linux-sgx/common/inc \
	-I../deps/linux-sgx/common/inc/internal \
  -I../deps/linux-sgx/external/epid-sdk

### Dependencies

MUSLCC=$(abspath sgx-lkl/build/host-musl/bin/musl-gcc)

.PHONY: deps
deps: deps/zlib deps/curl deps/protobuf-c deps/wolfssl

deps/zlib: | sgx-lkl
	mkdir -p deps && cd deps && git clone https://github.com/madler/zlib.git
	cd $@ && CFLAGS=-fPIC CC=$(MUSLCC) ./configure --prefix=$(abspath local) --static
	cd $@ && $(MAKE) install

# curl version 7_47_0 seems to work in combination with Intel's HTTPS proxy ...
deps/curl: deps/wolfssl | sgx-lkl
	mkdir -p deps && cd deps && git clone https://github.com/curl/curl.git
	cd $@ && git checkout curl-7_47_0
	cd $@ && ./buildconf
	cd $@ && CC=$(MUSLCC) ./configure --prefix=$(abspath local) --without-libidn --without-librtmp --without-libssh2 --without-libmetalink --without-libpsl --without-ssl --with-cyassl=$(abspath local) --disable-shared --with-pic
	cd $@ && $(MAKE) install

deps/protobuf-c: | sgx-lkl
	mkdir -p deps && cd deps && git clone https://github.com/protobuf-c/protobuf-c.git
	cd $@ && ./autogen.sh
	cd $@ && CC=$(MUSLCC) ./configure --prefix=$(abspath local) --disable-shared --with-pic
	cd $@ && $(MAKE) protobuf-c/libprotobuf-c.la
	cd $@ && mkdir -p ../../local/lib ../../local/include/protobuf-c
	cd $@ && cp protobuf-c/.libs/libprotobuf-c.a ../../local/lib
	cd $@ && cp protobuf-c/protobuf-c.h ../../local/include/protobuf-c

deps/wolfssl: | sgx-lkl
	mkdir -p deps && cd deps && git clone https://github.com/wolfSSL/wolfssl
	cd $@ && git checkout 57e5648a5dd734d1c219d385705498ad12941dd0
	cd $@ && patch -p1 < ../../../wolfssl.patch
	cd $@ && ./autogen.sh
	cd $@ && CC=$(MUSLCC) CFLAGS="-fPIC -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_ALWAYS_VERIFY_CB -DKEEP_PEER_CERT" ./configure --prefix=$(abspath local) --enable-writedup --enable-static --disable-shared --enable-keygen --enable-certgen --enable-certext --enable-tlsv10 # --enable-debug
	cd $@ && $(MAKE) install

ldpreload.so: CFLAGS+=-DUSE_WOLFSSL
ldpreload.so: ldpreload.c $(SRC) | sgx-lkl deps
	sgx-lkl/build/host-musl/bin/musl-gcc -o $@ $^ $(CFLAGS) $(INCLUDES) $(CFLAGSERRORS) -shared -fPIC -Llocal/lib -l:libcurl.a -l:libwolfssl.a -l:libprotobuf-c.a -l:libm.a -l:libz.a -ldl

sgx-lkl/apps/ratls/Makefile: | sgx-lkl
	cp -a ratls sgx-lkl/apps

sgx-lkl/apps/https-server/Makefile: | sgx-lkl
	cp -a https-server/ sgx-lkl/apps

sgx-lkl/apps/ratls/sgxlkl-miniroot-fs.img: ../sgxlkl-wolfssl-ssl-server sgx-lkl/apps/ratls/Makefile
	( cd sgx-lkl/apps/ratls && USER=`whoami` make )

sgx-lkl/apps/https-server/sgxlkl-miniroot-fs.img: ldpreload.so sgx-lkl/apps/https-server/Makefile
	( cd sgx-lkl/apps/https-server && USER=`whoami` make )

../sgxlkl-wolfssl-ssl-server: | sgx-lkl deps
	$(MAKE) -C .. sgxlkl-wolfssl-ssl-server

.PHONY: clean
clean:
	$(MAKE) -C sgx-lkl

.PHONY: distclean
distclean:
	$(RM) ldpreload.so
	$(RM) -r sgx-lkl deps/zlib deps/curl deps/protobuf-c deps/wolfssl local

EXTERNAL_IFACE ?= eth0
.PHONY: up-sgxlkl-network
up-sgxlkl-network:
	sudo ip tuntap add dev sgxlkl_tap0 mode tap user `whoami`
	sudo ip link set dev sgxlkl_tap0 up
	sudo ip addr add dev sgxlkl_tap0 10.0.1.254/24
	sudo iptables -I FORWARD -i sgxlkl_tap0 -o $(EXTERNAL_IFACE) -s 10.0.1.0/24 -m conntrack --ctstate NEW -j ACCEPT
	sudo iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	sudo iptables -t nat -I POSTROUTING -o $(EXTERNAL_IFACE) -j MASQUERADE
	socat -t10 TCP-LISTEN:1234,bind=10.0.1.254,reuseaddr,fork,range=10.0.1.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket &

.PHONY: down-sgxlkl-network
down-sgxlkl-network:
	sudo iptables -t nat -D POSTROUTING -o $(EXTERNAL_IFACE) -j MASQUERADE
	sudo iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	sudo iptables -D FORWARD -s 10.0.1.0/24 -i sgxlkl_tap0 -o $(EXTERNAL_IFACE) -m conntrack --ctstate NEW -j ACCEPT
	sudo ip tuntap del dev sgxlkl_tap0 mode tap
	pkill -f TCP-LISTEN:1234

.PHONY: run-https-server
run-https-server: sgx-lkl/apps/https-server/sgxlkl-miniroot-fs.img
	LD_PRELOAD=/ldpreload.so SGXLKL_TAP=sgxlkl_tap0 RATLS_AESMD_IP=10.0.1.254 SGXLKL_HEAP=268435456 SGXLKL_KEY=$(abspath sgx-lkl/build/config/enclave_debug.key ) sgx-lkl/build/sgx-lkl-run sgx-lkl/apps/https-server/sgxlkl-miniroot-fs.img /usr/bin/python /https-server.py

.PHONY: run-wolfssl-server
run-wolfssl-server: sgx-lkl/apps/ratls/sgxlkl-miniroot-fs.img
	SGXLKL_TAP=sgxlkl_tap0 SGXLKL_VERBOSE=1 RATLS_AESMD_IP=10.0.1.254 sgx-lkl/build/sgx-lkl-run sgx-lkl/apps/ratls/sgxlkl-miniroot-fs.img /sgxlkl-wolfssl-ssl-server
