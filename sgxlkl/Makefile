.PHONY=all
all: sgx-lkl/apps/ratls/sgxlkl-miniroot-fs.img sgx-lkl/apps/https-server/sgxlkl-miniroot-fs.img

.PHONY=sgx-lkl
sgx-lkl:
	[ ! -d $@ ] && git clone https://github.com/lsds/sgx-lkl.git || true
	cd sgx-lkl && $(MAKE)

SRC=../wolfssl-ra-attester.c \
	../wolfssl-ra.c \
	../ias_sign_ca_cert.c \
	../ias-ra.c \
	../nonsdk-ra-attester.c \
	../messages.pb-c.c \
	../sgx_report.S \
	../ra_tls_options.c

INCLUDES=-I.. -I/opt/intel/sgxsdk/include \
  -I../deps/linux-sgx/common/inc \
	-I../deps/linux-sgx/common/inc/internal \
  -I../deps/linux-sgx/external/epid-sdk-3.0.0

ldpreload.so: ldpreload.c $(SRC)
	local/bin/musl-gcc -o $@ $^ $(INCLUDES) $(CFLAGSERRORS) -shared -fPIC -Llocal/lib -l:libcurl.a -l:libwolfssl.a -l:libssl.a -l:libcrypto.a -l:libprotobuf-c.a -l:libm.a -l:libz.a -ldl

sgx-lkl/apps/ratls/Makefile sgx-lkl/apps/ratls/buildenv.sh: | sgx-lkl
	cp -a ratls sgx-lkl/apps

sgx-lkl/apps/https-server/Makefile sgx-lkl/apps/https-server/buildenv.sh: | sgx-lkl
	cp -a https-server/ sgx-lkl/apps

sgx-lkl/apps/ratls/sgxlkl-miniroot-fs.img: ldpreload.so sgx-lkl/apps/ratls/Makefile sgx-lkl/apps/ratls/buildenv.sh | sgx-lkl/apps/ratls
	( cd sgx-lkl/apps/ratls && USER=`whoami` make )

sgx-lkl/apps/https-server/sgxlkl-miniroot-fs.img: ldpreload.so sgx-lkl/apps/https-server/Makefile sgx-lkl/apps/https-server/buildenv.sh | sgx-lkl/apps/https-server
	( cd sgx-lkl/apps/https-server && USER=`whoami` make )

.PHONY=clean
clean:
	$(MAKE) -C sgx-lkl

.PHONY=distclean
distclean:
	$(RM) ldpreload.so
	$(RM) -r sgx-lkl

EXTERNAL_IFACE ?= eth0
.PHONY=up-sgxlkl-network
up-sgxlkl-network:
	sudo ip tuntap add dev sgxlkl_tap0 mode tap user `whoami`
	sudo ip link set dev sgxlkl_tap0 up
	sudo ip addr add dev sgxlkl_tap0 10.0.1.254/24
	sudo iptables -I FORWARD -i sgxlkl_tap0 -o $(EXTERNAL_IFACE) -s 10.0.1.0/24 -m conntrack --ctstate NEW -j ACCEPT
	sudo iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	sudo iptables -t nat -I POSTROUTING -o $(EXTERNAL_IFACE) -j MASQUERADE
	socat -t10 TCP-LISTEN:1234,bind=10.0.1.254,reuseaddr,fork,range=10.0.1.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket &

.PHONY=down-sgxlkl-network
down-sgxlkl-network:
	sudo iptables -t nat -D POSTROUTING -o $(EXTERNAL_IFACE) -j MASQUERADE
	sudo iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	sudo iptables -D FORWARD -s 10.0.1.0/24 -i sgxlkl_tap0 -o $(EXTERNAL_IFACE) -m conntrack --ctstate NEW -j ACCEPT
	sudo ip tuntap del dev sgxlkl_tap0 mode tap
	pkill -f TCP-LISTEN:1234

.PHONY=run-https-server
run-https-server:
	LD_PRELOAD=/ldpreload.so SGXLKL_TAP=sgxlkl_tap0 RATLS_AESMD_IP=10.0.1.254 SGXLKL_HEAP=268435456 SGXLKL_KEY=$(abspath sgx-lkl/build/config/enclave_debug.key ) sgx-lkl/build/sgx-lkl-run sgx-lkl/apps/https-server/sgxlkl-miniroot-fs.img /usr/bin/python /https-server.py

.PHONY=run-wolfssl-server
run-wolfssl-server:
	SGXLKL_TAP=sgxlkl_tap0 SGXLKL_VERBOSE=1 RATLS_AESMD_IP=10.0.1.254 sgx-lkl/build/sgx-lkl-run sgx-lkl/apps/ratls/sgxlkl-miniroot-fs.img /sgxlkl-wolfssl-ssl-server
