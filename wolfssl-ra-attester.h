#include <stdint.h>
#include <ra-attester.h>

void wolfssl_create_key_and_x509
(
    uint8_t* der_key,
    int* der_key_len,
    uint8_t* der_cert,
    int* der_cert_len,
    const struct ra_tls_options* opts
);
