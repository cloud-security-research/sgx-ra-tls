#include "ra-attester.h"

void mbedtls_create_key_and_x509
(
    mbedtls_pk_context* key,
    mbedtls_x509_crt* cert,
    const struct ra_tls_options* opts
);
