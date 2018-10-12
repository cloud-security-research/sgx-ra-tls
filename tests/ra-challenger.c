#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef OPENSSL
#include <openssl/ssl.h>
#endif

#include "ra-challenger.h"

/**
 * Read DER-encoded cert from argv[1] and verify.
 *
 * This is a simple unit test for the verification logic.
 */
int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

#ifdef OPENSSL
    OpenSSL_add_all_algorithms();
#endif

    uint8_t der_crt[2*4096];

    int fd = open(argv[1], O_RDONLY);
    int32_t der_crt_len = read(fd, der_crt, sizeof(der_crt));
    assert(der_crt_len > 0);

    assert(0 == verify_sgx_cert_extensions(der_crt, der_crt_len));
    return 0;
}
