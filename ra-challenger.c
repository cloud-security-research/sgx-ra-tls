/**
 * Code common to all challenger implementations (i.e., independent of
 * the TLS library).
 */

#define _GNU_SOURCE

#include <assert.h>
#include <string.h>

#if SGX_SDK
/* SGX SDK does not have this. */
void *memmem(const void *h0, size_t k, const void *n0, size_t l);
#endif

#include "ra-challenger_private.h"
#include "ra-challenger.h"

#define OID(N) {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, (N)}

const uint8_t ias_response_body_oid[]    = OID(0x02);
const uint8_t ias_root_cert_oid[]        = OID(0x03);
const uint8_t ias_leaf_cert_oid[]        = OID(0x04);
const uint8_t ias_report_signature_oid[] = OID(0x05);

const size_t ias_oid_len = sizeof(ias_response_body_oid);

void find_oid
(
     const unsigned char* ext, size_t ext_len,
     const unsigned char* oid, size_t oid_len,
     unsigned char** val, size_t* len
)
{
    uint8_t* p = memmem(ext, ext_len, oid, oid_len);
    assert(p != NULL);

    p += oid_len;

    // three bytes encoding criticality 0x01, 0x01, 0xFF
    int i = 0;
#if 0
    // Enable again if extension is deemed critical. Most TLS
    // implementation will fail validation of a certificate with
    // unknown critical extensions.
    assert(p[i++] == 0x01);
    assert(p[i++] == 0x01);
    assert(p[i++] == 0xFF);
#endif

    // Now comes the octet string
    assert(p[i++] == 0x04); // tag for octet string
    assert(p[i++] == 0x82); // length encoded in two bytes
    *len  =  p[i++] << 8;
    *len +=  p[i++];
    *val  = &p[i++];
}

/* This func removes the need for user app to know SGX-related const */
int get_measurements_size() {
    return SGX_HASH_SIZE;
}

/** Returns mr_enclave and mr_signer strings from SGX quote from DER cert
 *  if pointers are provided. User is responsible to allocate strings
 *  mr_enclave and mr_signer of size SGX_HASH_SIZE.
 *  NOTE: This func removes the need for user app to know sgx_quote struct. */
void get_measurements_from_cert(unsigned char* der, int der_len,
        unsigned char* mr_enclave, unsigned char* mr_signer)
{
    sgx_quote_t quote;
    get_quote_from_cert(der, der_len, &quote);
    sgx_report_body_t* body = &quote.report_body;

    if (mr_enclave)
        memcpy(mr_enclave, body->mr_enclave.m, SGX_HASH_SIZE);
    if (mr_signer)
        memcpy(mr_signer, body->mr_signer.m, SGX_HASH_SIZE);
}
