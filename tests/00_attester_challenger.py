#!/usr/bin/env python

import os
from subprocess import *
from time import sleep
from shlex import split
import sys


# Create RA-TLS certificates with three different TLS
# libraries. Verifies each of the three certificates with every TLS
# library. Uses Graphene-SGX to run the code in an enclave.

class TestCase:

    socat_process = None

    def setup(self):
        self.socat_process = Popen("exec socat -t10 TCP-LISTEN:1234,bind=127.0.0.1,reuseaddr,fork,range=127.0.0.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket", shell=True)

        sleep(1)
        assert self.socat_process.poll() == None

    def teardown(self):
        check_call(split('rm -rf /tmp/openssl.crt /tmp/wolfssl.crt /tmp/mbedtls.crt'))
        if self.socat_process:
            self.socat_process.terminate()
            self.socat_process = None

    def verify(self):
        pass

    def main(self) :
        with open('/tmp/openssl.crt', 'w') as f:
            check_call(split("deps/graphene/Runtime/pal-Linux-SGX openssl-ra-attester"),
                       stdout=f)
        with open('/tmp/wolfssl.crt', 'w') as f:
            check_call(split("deps/graphene/Runtime/pal-Linux-SGX wolfssl-ra-attester"),
                       stdout=f)
        with open('/tmp/mbedtls.crt', 'w') as f:
            check_call(split("deps/graphene/Runtime/pal-Linux-SGX mbedtls-ra-attester"),
                       stdout=f)

        for lib in ['mbedtls', 'wolfssl', 'openssl']:
            check_call(split('./openssl-ra-challenger /tmp/%s.crt' % (lib) ))
            check_call(split('./wolfssl-ra-challenger /tmp/%s.crt' % (lib) ))
            check_call(split('./mbedtls-ra-challenger /tmp/%s.crt' % (lib) ))

if __name__ == '__main__':
    tc = TestCase()
    try:
        tc.setup()
        tc.main()
    finally:
        tc.teardown()
