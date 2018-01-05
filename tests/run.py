#!/usr/bin/env python

from subprocess import *
from time import sleep
import sys

def sgx_sdk_test_cases() :
    for client in ['mbedtls-client', 'wolfssl-client', 'openssl-client'] :
        server_process = None
        try:
            server_process = Popen('exec ./App -s',
                                   cwd='deps/wolfssl-examples/SGX_Linux',
                                   shell=True)
            sleep(5)

            # Verify server process started correctly.
            assert server_process.poll() == None

            check_call("./"+client)
        finally:
            if server_process:
                server_process.terminate()

def graphene_sgx_test_cases():

    socat_process = Popen("exec socat -t10 TCP-LISTEN:1234,bind=127.0.0.1,reuseaddr,fork,range=127.0.0.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket", shell=True)

    sleep(1)
    assert socat_process.poll() == None

    try:
        server_process = None
        for server in ['wolfssl-ssl-server', 'mbedtls-ssl-server'] :
            cmd = "exec deps/graphene/Runtime/pal-Linux-SGX ./%s" % (server)
            server_process = Popen(cmd, shell=True)
            sleep(10)
            assert server_process.poll() == None

            for client in ['mbedtls-client', 'wolfssl-client', 'openssl-client'] :
                check_call('./' + client)

            server_process.terminate()
            sleep(1)
            assert server_process.poll() == 0
    finally:
        socat_process.terminate()
        if server_process != None:
            if server_process.poll() == None:
                server_process.terminate()

def main() :
    sgx_sdk_test_cases()
    graphene_sgx_test_cases()

if __name__ == '__main__':
    main()
