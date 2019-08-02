# Description

This project demonstrates how to provision an SGX application with secrets after remotely attesting it. The application in our case is Redis. A Redis server can be configured to require clients to authenticate/authorize with a password before accepting any commands from them. The password is usually provided either in a configuration file or as a command line option. This repository demonstrates how to provision the password only after attesting the Redis server.

Redis server runs inside an SGX enclave with the help of Graphene. After instantiating the enclave, but before the Redis server runs, we execute additional code (captured in the `redis-server-provision-secret.so` helper library and LDPRELOADed in the Redis manifest) to remotely attest to a verifier. The verifier has the expected identity of the Redis server hard-coded and only releases the password after successfully attesting the Redis server.

The Redis server is completely unmodified. This project assumes that Redis is called with `--requirepass <dummystring>`. After the helper library receives the password from the secret provisioning service, it overwrites this command-line argument with `--requirepass <received-secret>`.

The Redis server communicates securely with the secret provisioning service over mutually authenticated TLS. The provisioning service uses a standard (self-signed) [X.509 certificate](verifier-crt.pem) as its identity. The Redis server uses an RA-TLS certificate to authenticate to the provisioning service. The provisioning service has the Redis server's SGX identity backed in during build time (cf. [redis_server_sgx_identity.c](redis_server_sgx_identity.c)). The provisioning service verifies the SGX identity information in the RA-TLS certificate before sending the secret to the remote party.

```
                   X.509     TLS    RA-TLS          plain text
Secret Provisioning   <-------------->   Redis    <---------->  Client
Service (verifier)
```

This demonstrator focuses on the remote provisioning of the password. The Redis server and client communicate in plain text, exposing the password to any man-in-the-middle attacker. To prevent this, the Redis server and client should also use an encrypted communication channel; either by enabling [TLS in Redis itself](https://github.com/antirez/redis/pull/4855/) or through Graphene's network shield.

# Build

Sequence is important here. First build the Redis server since its identity is hard-coded into the verifier. Otherwise, the verifier will reject the Redis server and not send any secrets.

``` bash
make redis-server.token && make verifier
```

# Run

Start the verifier

``` bash
./verifier
```

Start the Redis server

``` bash
make redis-server-run
```

The server will print couple messages after the verifier successfully released the password.

Connect to the Redis server as a client

``` bash
deps/redis/src/redis-cli
```

Type "auth [password]" to authenticate to the server.

# Notes

## On weak vs strong symbols, dlsym and LD_PRELOAD

For transparent provisioning of the secret password to Redis, we initially hoped to overload existing functions in Redis via LD_PRELOAD. However, LD_PRELOAD of course only works if the symbol you are trying to override is resolved dynamically which Redis' internal functions are not. LD_PRELOAD is only able to overwrite functions residing in shared libraries.

## Patching command-line arguments of Redis

The current implementation patches command-line argument `--requirepass <dummystring>` to Redis to inject the secret password. It relies on a clever trick to modify argv through a constructor in the shared library (cf. https://sourceware.org/ml/libc-help/2009-11/msg00006.html). Alternatively, one could create or modify the Redis configuration file (redis.conf) with the password.
