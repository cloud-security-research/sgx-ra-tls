#!/usr/bin/env python

import os
from subprocess import *
from time import sleep
from shlex import split
import sys

class MutualAttestationTestCase():
    socat_process  = None
    server_process = None
    client_process = None
    
    def setup(self):
        self.socat_process = Popen("exec socat -t10 TCP-LISTEN:1234,bind=127.0.0.1,reuseaddr,fork,range=127.0.0.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket", shell=True)
        sleep(1)
        assert self.socat_process.poll() == None
        
    def teardown(self):
        if self.socat_process:
            self.socat_process.terminate()
            self.socat_process = None
        if self.server_process:
            if self.server_process.poll() == None:
                self.server_process.terminate()
            self.server_process = None
        if self.client_process:
            if self.client_process.poll() == None:
                self.client_process.terminate()
            self.client_process = None
            
    def verify(self):
        pass
    def main(self):
        cmd = 'exec deps/graphene/Runtime/pal-Linux-SGX wolfssl-ssl-server-mutual'
        self.server_process = Popen(cmd, shell=True)
        sleep(10)

        cmd = 'exec deps/graphene/Runtime/pal-Linux-SGX wolfssl-client-mutual'
        self.client_process = Popen(cmd, shell=True)
        for _ in range(10):
            if self.client_process.poll() != None:
                break
            sleep(1)
        
        assert (self.client_process.poll() == 0)

class GrapheneSGXTestCase():
    socat_process = None
    server_process = None
    
    def setup(self):
        self.socat_process = Popen("exec socat -t10 TCP-LISTEN:1234,bind=127.0.0.1,reuseaddr,fork,range=127.0.0.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket", shell=True)
        sleep(1)
        assert self.socat_process.poll() == None
        
    def teardown(self):
        if self.socat_process:
            self.socat_process.terminate()
        if self.server_process:
            if self.server_process.poll() == None:
                self.server_process.terminate()
                self.server_process = None

    def main(self):
        for server in ['wolfssl-ssl-server', 'mbedtls-ssl-server'] :
            cmd = "exec deps/graphene/Runtime/pal-Linux-SGX ./%s" % (server)
            self.server_process = Popen(cmd, shell=True)
            sleep(10)
            assert self.server_process.poll() == None

            for client in ['mbedtls-client', 'wolfssl-client', 'openssl-client -p 11111'] :
                check_call(split('./' + client))

            self.server_process.terminate()
            for i in range(5):
                if self.server_process.poll():
                    break
                sleep(1)
            sigterm = 15
            assert self.server_process.poll() == sigterm
