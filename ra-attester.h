#ifndef _RA_ATTESTER_H_
#define _RA_ATTESTER_H_

#include <sgx_quote.h>

struct ra_tls_options {
    sgx_spid_t spid;
    sgx_quote_sign_type_t quote_type;
    /* \0 terminated file name; libcurl, used to interact with IAS,
       basically expects a file name. It is super-complicated to pass
       a memory buffer with the certificate and key to it. */
    const char ias_key_file[512];
    const char ias_cert_file[512];
    /* \0 terminated string of domain name/IP and port, e.g.,
       test-as.sgx.trustedservices.intel.com:443 */
    const char ias_server[512];
};

struct ecdsa_ra_tls_options {
    char subscription_key[32];
};

void create_key_and_x509
(
    uint8_t* der_key,
    int* der_key_len,
    uint8_t* der_cert,
    int* der_cert_len,
    const struct ra_tls_options* opts
);

void create_key_and_x509_pem
(
    uint8_t* pem_key,
    int* pem_key_len,
    uint8_t* pem_cert,
    int* pem_cert_len,
    const struct ra_tls_options* opts
);

#ifdef RATLS_ECDSA
void ecdsa_create_key_and_x509
(
    uint8_t* der_key,
    int* der_key_len,
    uint8_t* der_cert,
    int* der_cert_len,
    const struct ecdsa_ra_tls_options* opts
);
#endif

void ra_tls_create_report(
    sgx_report_t* report
);
#endif
