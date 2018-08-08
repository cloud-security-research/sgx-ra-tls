#include "ra-attester.h"

struct ra_tls_options my_ra_tls_options = {
    .spid = {{0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00}},
    .quote_type = SGX_UNLINKABLE_SIGNATURE,
    .ias_key_file = "./ias-client-key.pem",
    .ias_cert_file = "./ias-client-cert.pem",
    .ias_server = "test-as.sgx.trustedservices.intel.com:443"
};
