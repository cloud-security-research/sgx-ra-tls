#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
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

#ifdef OPENSSL
    OpenSSL_add_all_algorithms();
#endif

    if (argc < 2) {
        fprintf(stderr, "Usage: %s certificate\n", argv[0]);
        return 1;
    }
    
    int fd = open(argv[1], O_RDONLY);
    struct stat st;
    fstat(fd, &st);
    uint8_t der_crt[st.st_size];
    int32_t der_crt_len = read(fd, der_crt, st.st_size);
    assert(der_crt_len == st.st_size);

    int rc = verify_sgx_cert_extensions(der_crt, der_crt_len);
    printf("SGX RA-TLS certificate verification ... %s\n", (rc == 0) ? "SUCCESS" : "FAIL");

    dprintf_ratls_cert(STDOUT_FILENO, der_crt, der_crt_len);
    
    return rc;
}
