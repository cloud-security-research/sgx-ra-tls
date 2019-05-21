#!/usr/bin/env python

import os
from subprocess import *
from time import sleep
from shlex import split
import sys


# Create ECDSA-based RA-TLS certificates with different TLS
# libraries. Verify each certificate with every TLS library. Use
# Graphene-SGX to run the code in an enclave.

class TestCase:

    socat_process = None

    def setup(self):
        self.quoteservice = Popen("exec deps/SGXDataCenterAttestationPrimitives/SampleCode/QuoteServiceSample/app", shell=True)

        sleep(1)
        assert self.quoteservice.poll() == None

    def teardown(self):
        check_call(split('rm -rf /tmp/openssl.crt /tmp/wolfssl.crt /tmp/mbedtls.crt'))
        if self.quoteservice:
            self.quoteservice.terminate()
            self.quoteservice = None

    def verify(self):
        pass

    def main(self) :
        # libs = ['mbedtls', 'wolfssl', 'openssl']
        libs = ['wolfssl']
        for lib in libs:
            check_call(split("deps/graphene/Runtime/pal-Linux-SGX %s-ra-attester ecdsa" % (lib)))
            check_call(split("cp crt.der /tmp/%s.crt" % (lib)))

            # check_call(split('./openssl-ra-challenger /tmp/%s.crt' % (lib)))
            check_call('LD_LIBRARY_PATH=deps/local/lib ./wolfssl-ra-challenger /tmp/%s.crt ecdsa' % (lib), shell=True)
            # check_call(split('./mbedtls-ra-challenger /tmp/%s.crt' % (lib)))

if __name__ == '__main__':
    tc = TestCase()
    try:
        tc.setup()
        tc.main()
    finally:
        tc.teardown()
