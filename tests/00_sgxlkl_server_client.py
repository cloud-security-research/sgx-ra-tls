#!/usr/bin/env python

import os
from subprocess import *
from time import sleep
from shlex import split
import sys

external_iface = 'eth0'
if 'EXTERNAL_IFACE' in os.environ:
    external_iface = os.environ['EXTERNAL_IFACE']

class SGXLKLTestCase():
    socat_process = None

    def setup_iptables(self):
        cmds = ["sudo ip tuntap add dev sgxlkl_tap0 mode tap user `whoami`",
                "sudo ip link set dev sgxlkl_tap0 up",
                "sudo ip addr add dev sgxlkl_tap0 10.0.1.254/24",
                "sudo iptables -I FORWARD -i sgxlkl_tap0 -o "+external_iface+" -s 10.0.1.0/24 -m conntrack --ctstate NEW -j ACCEPT",
                "sudo iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                "sudo iptables -t nat -I POSTROUTING -o "+external_iface+" -j MASQUERADE"]

        for cmd in cmds:
            check_call(cmd, shell=True)

    def setup(self):
        self.setup_iptables()
    
        self.socat_process = Popen("exec socat -t10 TCP-LISTEN:1234,bind=10.0.1.254,reuseaddr,fork,range=10.0.1.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket", shell=True)
        sleep(1)
        assert self.socat_process.poll() == None
        
    def teardown_iptables(self):
        cmds = ["sudo iptables -t nat -D POSTROUTING -o "+external_iface+" -j MASQUERADE",
                "sudo iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                "sudo iptables -D FORWARD -s 10.0.1.0/24 -i sgxlkl_tap0 -o "+external_iface+" -m conntrack --ctstate NEW -j ACCEPT",
                "sudo ip tuntap del dev sgxlkl_tap0 mode tap"]

        for cmd in cmds:
            check_call(split(cmd))
        
    def teardown(self):
        self.socat_process.terminate()
        self.socat_process = None
        self.teardown_iptables()

    def main(self):
        server_process = None
        cmd = 'exec sgxlkl/sgx-lkl/build/sgx-lkl-run sgxlkl/sgx-lkl/apps/ratls/sgxlkl-miniroot-fs.img /sgxlkl-wolfssl-ssl-server'
        env = dict(os.environ)
        env.update({'SGXLKL_TAP' : 'sgxlkl_tap0',
                    'SGXLKL_VERBOSE' : '1',
                    'RATLS_AESMD_IP' : '10.0.1.254'})

        server_process = Popen(cmd, env=env, shell=True)
        sleep(10)
        assert server_process.poll() == None

        check_call(split('./openssl-client -p 11111 -h 10.0.1.1'))

        server_process.terminate()
        sleep(1)
        assert server_process.poll() != None
