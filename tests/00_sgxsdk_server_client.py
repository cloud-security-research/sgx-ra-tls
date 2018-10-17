#!/usr/bin/env python

import os
from subprocess import *
from time import sleep
from shlex import split
import sys

class SGXSDKTestCase():
    def setup(self):
        pass
    def teardown(self):
        pass
    def main(self):
        for client in ['mbedtls-client', 'wolfssl-client', 'openssl-client -p 11111'] :
            server_process = None
            try:
                server_process = Popen('exec ./App -s',
                                       cwd='deps/wolfssl-examples/SGX_Linux',
                                       shell=True)
                sleep(5)

                # Verify server process started correctly.
                assert server_process.poll() == None

                check_call(split("./"+client))
            finally:
                if server_process:
                    server_process.terminate()
