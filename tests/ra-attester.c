#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "ra-attester.h"

extern struct ecdsa_ra_tls_options my_ecdsa_ra_tls_options;
extern struct ra_tls_options my_ra_tls_options;

static void write_buffer(const unsigned char* buf,
                         int32_t len,
                         const char* filename)
{
    int fd = open(filename, O_CREAT | O_WRONLY, S_IRWXU);
    assert(fd > 0);
    ssize_t written = write(fd, buf, len);
    assert(written == len);
    close(fd);
}

static void usage(char* argv[]) {
    fprintf(stderr, "Usage: %s [epid|ecdsa]\n", argv[0]);
}

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;
    
    uint8_t der_key[2048];
    uint8_t der_crt[4*4096];
    int32_t der_key_len = sizeof(der_key);
    int32_t der_crt_len = sizeof(der_crt);

    if (argc < 2) {
        usage(argv);
        return 1;
    }
    
    if (0 == strcmp(argv[1], "epid")) {
        create_key_and_x509(der_key, &der_key_len,
                            der_crt, &der_crt_len,
                            &my_ra_tls_options);
    } else if (0 == strcmp(argv[1], "ecdsa")) {
#ifdef RATLS_ECDSA
        ecdsa_create_key_and_x509(der_key, &der_key_len,
                                  der_crt, &der_crt_len,
                                  &my_ecdsa_ra_tls_options);
#else
        assert(0 && "not supported");
#endif
    } else {
        usage(argv);
        return 1;
    }

    write_buffer(der_crt, der_crt_len, "crt.der");
    write_buffer(der_key, der_key_len, "key.der");
}
