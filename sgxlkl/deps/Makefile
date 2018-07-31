all: ../local/bin/musl-gcc ../local/lib/libssl.a ../local/lib/libcrypto.a

musl-1.1.19/configure:
	[ ! -e $@ ] && wget https://git.musl-libc.org/cgit/musl/snapshot/musl-1.1.19.tar.gz || true
	tar xfz musl-1.1.19.tar.gz

../local/bin/musl-gcc: musl-1.1.19/configure
	cd musl-1.1.19 && pwd
	cd musl-1.1.19 && ./configure --prefix=$(abspath ../local)
	cd musl-1.1.19 && make -j8
	cd musl-1.1.19 && make install

../local/lib/libssl.a ../local/lib/libcrypto.a:
	[ ! -d openssl ] && git clone https://github.com/openssl/openssl.git || true
	( cd openssl && CC=$(abspath ../local/bin/musl-gcc) ./config --prefix=$(abspath ../local) no-shared -fPIC && CC=$(abspath ../local/bin/musl-gcc) make && make install )
