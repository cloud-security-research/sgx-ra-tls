#include <stdio.h>

#include "ra-attester.h"

extern struct ra_tls_options my_ra_tls_options;

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;
    
    uint8_t der_key[2048];
    uint8_t der_crt[2*4096];
    int32_t der_key_len = sizeof(der_key);
    int32_t der_crt_len = sizeof(der_crt);
    
    create_key_and_x509(der_key, &der_key_len,
                        der_crt, &der_crt_len,
                        &my_ra_tls_options);

    fwrite(der_crt, der_crt_len, 1, stdout);
    fflush(stdout);
}
