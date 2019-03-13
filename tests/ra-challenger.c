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
    (void) argc;
    (void) argv;

#ifdef OPENSSL
    OpenSSL_add_all_algorithms();
#endif

    if (argc < 3) {
        fprintf(stderr, "Usage: %s certificate [epid|ecdsa]\n", argv[0]);
        return 1;
    }
    
    uint8_t der_crt[16*1024];

    int fd = open(argv[1], O_RDONLY);
    struct stat st;
    fstat(fd, &st);
    assert(st.st_size <= (int) sizeof(der_crt));
    int32_t der_crt_len = read(fd, der_crt, sizeof(der_crt));
    assert(der_crt_len > 0);

    if (0 == strcmp(argv[2], "epid")) {
        assert(0 == verify_sgx_cert_extensions(der_crt, der_crt_len));
    } else if (0 == strcmp(argv[2], "ecdsa")) {
        assert(0 == ecdsa_verify_sgx_cert_extensions(der_crt, der_crt_len));
    }

    sgx_quote_t quote;
    get_quote_from_cert(der_crt, der_crt_len, &quote);
    sgx_report_body_t* body = &quote.report_body;

    printf("Certificate's SGX information:\n");
    printf("MRENCLAVE = ");
    for (int i=0; i < SGX_HASH_SIZE; ++i) printf("%02x", body->mr_enclave.m[i]);
    printf("\n");
    
    printf("MRSIGNER  = ");
    for (int i=0; i < SGX_HASH_SIZE; ++i) printf("%02x", body->mr_signer.m[i]);
    printf("\n");
    
    return 0;
}
