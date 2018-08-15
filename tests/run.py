#!/usr/bin/env python

import os
from subprocess import *
from time import sleep
from shlex import split
import sys

def sgx_sdk_test_cases() :
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

            for client in ['mbedtls-client', 'wolfssl-client', 'openssl-client -p 11111'] :
                check_call(split('./' + client))

            server_process.terminate()
            sleep(1)
            assert server_process.poll() == 0
    finally:
        socat_process.terminate()
        if server_process != None:
            if server_process.poll() == None:
                server_process.terminate()

def sgxlkl_setup_iptables():
    cmds = ["sudo ip tuntap add dev sgxlkl_tap0 mode tap user `whoami`",
            "sudo ip link set dev sgxlkl_tap0 up",
            "sudo ip addr add dev sgxlkl_tap0 10.0.1.254/24",
            "sudo iptables -I FORWARD -i sgxlkl_tap0 -o eth0 -s 10.0.1.0/24 -m conntrack --ctstate NEW -j ACCEPT",
            "sudo iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "sudo iptables -t nat -I POSTROUTING -o eth0 -j MASQUERADE"]

    for cmd in cmds:
        check_call(cmd, shell=True)

def sgxlkl_teardown_iptables():
    cmds = ["sudo iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
            "sudo iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "sudo iptables -D FORWARD -s 10.0.1.0/24 -i sgxlkl_tap0 -o eth0 -m conntrack --ctstate NEW -j ACCEPT",
            "sudo ip tuntap del dev sgxlkl_tap0 mode tap"]

    for cmd in cmds:
        check_call(split(cmd))

# This does not setup the iptable rules required for SGX-LKL to communicate with the outside world!
def sgxlkl_test_case():

    sgxlkl_setup_iptables()
    
    socat_process = Popen("exec socat -t10 TCP-LISTEN:1234,bind=10.0.1.254,reuseaddr,fork,range=10.0.1.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket", shell=True)
    sleep(1)
    assert socat_process.poll() == None

    try:
        server_process = None
        cmd = 'exec sgxlkl/sgx-lkl/build/sgx-lkl-run sgxlkl/sgx-lkl/apps/ratls/sgxlkl-miniroot-fs.img /sgxlkl-wolfssl-ssl-server'
        env = dict(os.environ)
        env.update({'SGXLKL_TAP' : 'sgxlkl_tap0',
                    'SGXLKL_VERBOSE' : '1',
                    'RATLS_AESMD_IP' : '10.0.1.254'})
        print env
        server_process = Popen(cmd, env=env, shell=True)
        sleep(10)
        assert server_process.poll() == None

        check_call(split('./openssl-client -p 11111 -h 10.0.1.1'))

        server_process.terminate()
        sleep(1)
        assert server_process.poll() != None
        
    finally:
        socat_process.terminate()
        if server_process != None:
            if server_process.poll() == None:
                server_process.terminate()
        sgxlkl_teardown_iptables()

def main() :
    sgx_sdk_test_cases()
    graphene_sgx_test_cases()
    sgxlkl_test_case()

if __name__ == '__main__':
    main()
