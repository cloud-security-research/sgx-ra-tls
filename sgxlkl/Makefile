all: sgx-lkl sgx-lkl/apps/ratls/sgxlkl-miniroot-fs.img

sgx-lkl:
	[ ! -d $@ ] && git clone https://github.com/lsds/sgx-lkl.git || true
	cd sgx-lkl && $(MAKE)

sgx-lkl/apps/ratls: sgx-lkl
	cp -a ratls sgx-lkl/apps

sgx-lkl/apps/ratls/sgxlkl-miniroot-fs.img: sgx-lkl/apps/ratls
	( cd sgx-lkl/apps/ratls && USER=`whoami` $(MAKE) )

clean:
	make -C sgx-lkl $@

distclean:
	$(RM) -r sgx-lkl/apps/ratls

.PHONY: all clean distclean sgx-lkl
