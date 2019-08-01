# Description

This project demonstrates how to provision an SGX application with secrets after remotely attesting it. We demonstrate this with two applications, one of which is Redis. Redis can be configured with a password which clients must provide before the server accepts commands from them. The password is usually provided either in a configuration file or as a command line argument. We demonstrate how to provision the password only after attesting the Redis server. We also have a second [application](show-secrets.c) to demonstrate how to provision secrets passed in environment variables.

The Redis server runs inside an SGX enclave with the help of Graphene. After instantiating the enclave, but before the Redis server runs, we execute additional code (captured in the `redis-server-grab-secret.so` helper library and LDPRELOADed in the Redis manifest) to remotely attest to a [secret provisioning service](secret-provisioning-service.c). The secret provisioning service only releases the password to the Redis server after successfully verifying its SGX identity.

The Redis server is completely unmodified. This project assumes that Redis is called with `--requirepass <placeholder>`. After the helper library receives the password from the secret provisioning service, it overwrites this command-line argument with `--requirepass <received-secret>`.

The Redis server communicates securely with the secret provisioning service over mutually authenticated TLS. The provisioning service uses a standard (self-signed) [X.509 certificate](secret-provisioning-service-crt.pem) as its identity. The Redis server uses an RA-TLS certificate to authenticate to the provisioning service. The provisioning service has the Redis server's SGX identity backed at build time (cf. [redis_server_sgx_identity.c](redis_server_sgx_identity.c)). The provisioning service verifies the SGX identity information in the RA-TLS certificate before sending the secret to the remote party.

```
                   X.509     TLS    RA-TLS          plain text
Secret Provisioning   <-------------->   Redis    <---------->  Client
Service (verifier)
```

This demonstrator focuses on the remote provisioning of the password. The Redis server and client communicate in plain text, exposing the password to any man-in-the-middle attacker. To prevent this, the Redis server and client should also use an encrypted communication channel; either by enabling [TLS in Redis itself](https://github.com/antirez/redis/pull/4855/) or through Graphene's network shield.

# Build

Prepare everything by executing `make`. To avoid building Redis from source, specify the path to an existing Redis binary as follows: `export REDIS_SERVER_BINARY=/usr/bin/redis-server`.

# Run

Start the secret provisioning service with `./secret-provisioning-service`. A single service delivers secrets to multiple applications based on their SGX identity.

Expose AESMD's domain socket via TCP such that it can be reached from within Graphene

``` bash
socat -t10 TCP-LISTEN:1234,bind=127.0.0.1,reuseaddr,fork,range=127.0.0.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket &
```

Start the Redis server with `make redis-server-run`.

Redis prints a couple of messages after the secret provisioning service released the password.

Test with `[redis/src/]redis-cli -a intelsgxrocks! ping`. [Output should be](https://redis.io/topics/rediscli) `PONG`. A different password will result in Redis telling you that the authentication failed.

The [show-secrets](show-secrets.c) application demonstrates how to provision a secret to an environment variable (in addition to a secret command line argument). Run the application with `make show-secrets-run`. It will print some messages, that are hopefully self-explanatory.

# Notes

## On weak vs strong symbols, dlsym and LD_PRELOAD

For transparent provisioning of the secret password to Redis, we initially hoped to overload existing functions in Redis via LD_PRELOAD. However, LD_PRELOAD of course only works if the symbol you are trying to override is resolved dynamically which Redis' internal functions are not. LD_PRELOAD is only able to overwrite functions residing in shared libraries.

## Patching command-line arguments of Redis

The current implementation patches command-line argument `--requirepass <placeholder>` to Redis to inject the secret password. It relies on a clever trick to modify argv through a constructor in the shared library (cf. https://sourceware.org/ml/libc-help/2009-11/msg00006.html). Alternatively, one could create or modify the Redis configuration file (redis.conf) with the password. Note that the passing of argc, argv and envp to library constructors is glibc-specific behavior.
