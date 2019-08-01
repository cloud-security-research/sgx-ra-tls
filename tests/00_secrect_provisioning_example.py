#!/usr/bin/env python3

import os
from subprocess import Popen, run, PIPE
from time import sleep
from shlex import split
import sys
import unittest

class RedisProvisioningTestCase(unittest.TestCase):
    socat_process  = None
    verifier_process = None
    redis_process = None
    old_cwd = None

    # Expected by unittest.TestCase.
    # TODO: Unify setUp() and setup().
    def setUp(self):
        self.setup()
    
    def setup(self):
        self.socat_process = Popen("exec socat -t10 TCP-LISTEN:1234,bind=127.0.0.1,reuseaddr,fork,range=127.0.0.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket", shell=True)
        sleep(1)
        assert self.socat_process.poll() == None

        self.old_cwd = os.getcwd()
        os.chdir('apps/secret-provisioning-example')
        
        cmd = 'exec ./secret-provisioning-service'
        self.verifier_process = Popen(cmd, shell=True)
        sleep(2)
        
    def teardown(self):
        if self.socat_process:
            self.socat_process.terminate()
            self.socat_process = None
        if self.verifier_process:
            if self.verifier_process.poll() == None:
                self.verifier_process.terminate()
            self.verifier_process = None
        if self.redis_process:
            if self.redis_process.poll() == None:
                # .terminate() does not seem to work properly with
                # redis-server and this version of Graphene
                self.redis_process.kill()
            self.redis_process = None

    # Expected by unittest.TestCase.
    # TODO: Unify tearDown() and teardown().
    def tearDown(self):
        self.teardown()
        os.chdir(self.old_cwd)
        
    def verify(self):
        pass

    def test_redis_server(self):
        cmd = 'exec ../../deps/graphene/Runtime/pal-Linux-SGX ./redis-server.manifest.sgx --save "" --protected-mode no --requirepass XXXXX'
        self.redis_process = Popen(cmd, shell=True)
        for _ in range(10):
            if self.redis_process.poll() != None:
                break
            sleep(1)

        p = run('redis/src/redis-cli -a intelsgxrocks! ping',
                shell=True, stdout=PIPE, timeout=3)
        self.assertTrue(p.stdout.decode().strip() == "PONG")

        # redis-server may actually exit with non-zero return
        # status. That's fine.
        # assert (self.redis_process.poll() == 0)

    def test_show_secret(self):
        cmd = 'exec ../../deps/graphene/Runtime/pal-Linux-SGX ./show-secrets.manifest.sgx --requirepass XxxXXxxXX'
        p = Popen(cmd, shell=True, stdout=PIPE, env={'SECRET':'not-the-real-thing'})
        outs, errs = p.communicate(timeout=10)

        outs = outs.decode()
        
        self.assertTrue(outs.find('SECRET=42istheanswer') != -1)
        self.assertTrue(outs.find('Overwriting as `--requirepass 42istheanswer!`') != -1)
        
    def main(self):
        self.test_redis_server()
        self.test_show_secret()

if __name__ == '__main__':
    unittest.main()
