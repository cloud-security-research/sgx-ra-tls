#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

#include "ra-attester.h"

/* Use this in conjuction with Graphene-SGX, SCONE or SGX-LKL to
   expose the RA-TLS key and certificate as ordinary files to the
   application. This enables the use of RA-TLS without modifying the
   application simply by loading the key and certificate from a
   file. This is useful, for example, if the application cannot be
   modified (source code unavailable) or it is inconvenient to
   interface with C code (applications written for managed
   runtimes). */

uint8_t key[2048]; uint8_t crt[8192];
int key_len = sizeof(key);
int crt_len = sizeof(crt);

/* On SCONE and SGX-LKL /tmp is an in-memory file system protected by
   SGX. BEWARE: Graphene-SGX has no concept of a protected file system
   and writing the key to /tmp will expose it to the outside. */
#define FSROOT "/tmp"

static const char* key_path = FSROOT"/key";
static const char* crt_path = FSROOT"/crt";

extern struct ra_tls_options my_ra_tls_options;


/* We use a constructor function in combination with LD_PRELOAD to
   generate the key and certificate during the application's
   initialization. */
static __attribute__((constructor))
void init(void) {
    create_key_and_x509(key, &key_len, crt, &crt_len, &my_ra_tls_options);

    int fd = open(key_path, O_WRONLY|O_CREAT);
    assert(fd != -1);
    int ret = write(fd, key, key_len);
    assert(ret == key_len);
    close(fd);
    fd = open(crt_path, O_WRONLY|O_CREAT);
    assert(fd != -1);
    ret = write(fd, crt, crt_len);
    assert(ret == crt_len);
    close(fd);
}
