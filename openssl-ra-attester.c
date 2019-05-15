/* Code to create an extended X.509 certificate with OpenSSL. */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sgx_uae_service.h>

#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "ra-attester.h"
#include "ra.h"
#include "ra_private.h"
#include "ra-challenger_private.h"

static const uint32_t SHA256_DIGEST_SIZE = 256 / 8;

/**
 * Caller must allocate memory for certificate.
 * 
 * @param der_crt_len On entry contains the size of der_crt buffer. On return holds actual size of certificate in bytes.
 */
static
void generate_x509
(
    EVP_PKEY* key,   /* in */
    uint8_t* der_crt, /* out */
    int* der_crt_len, /* in/out */
    attestation_verification_report_t* attn_report
)
{
    X509* crt;
    crt = X509_new();
    
    X509_set_version(crt, 2);
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), 31536000L);

    X509_set_pubkey(crt, key);

    X509_NAME* name;
    name = X509_get_subject_name(crt);
    
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                               (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST",  MBSTRING_ASC,
                               (unsigned char *)"OR", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L",  MBSTRING_ASC,
                               (unsigned char *)"Hillsboro", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                               (unsigned char *)"Intel Inc.", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU",  MBSTRING_ASC,
                               (unsigned char *)"Intel Labs", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *)"SGX rocks!", -1, -1, 0);

    X509_set_issuer_name(crt, name);

    ASN1_OBJECT obj = { .data = ias_response_body_oid + 2,
                        .length = ias_oid_len - 2 };
    ASN1_OCTET_STRING val = { .data = attn_report->ias_report,
                              .length = attn_report->ias_report_len};
    X509_EXTENSION ex = { &obj, 0, &val };
    X509_add_ext(crt, &ex, -1);

    obj.data   = ias_root_cert_oid + 2;
    val.data   = attn_report->ias_sign_ca_cert;
    val.length = attn_report->ias_sign_ca_cert_len;
    X509_add_ext(crt, &ex, -1);

    obj.data   = ias_leaf_cert_oid + 2;
    val.data   = attn_report->ias_sign_cert;
    val.length = attn_report->ias_sign_cert_len;
    X509_add_ext(crt, &ex, -1);

    obj.data   = ias_report_signature_oid + 2;
    val.data   = attn_report->ias_report_signature;
    val.length = attn_report->ias_report_signature_len;
    X509_add_ext(crt, &ex, -1);

    X509_sign(crt, key, EVP_sha256());

    /* Encode X509 as DER. */
    int len = i2d_X509(crt, NULL);
    assert(len <= *der_crt_len);
    i2d_X509(crt, &der_crt);
    *der_crt_len = len;

    X509_free(crt);
    crt = NULL;
}

void sha256_rsa_pubkey
(
    unsigned char hash[SHA256_DIGEST_SIZE],
    RSA* key
)
{
    int len = i2d_RSAPublicKey(key, NULL);
    assert(len > 0);
    assert(len == rsa_pub_3072_raw_der_len);
    
    unsigned char buf[len];
    unsigned char* p = buf;
    len = i2d_RSAPublicKey(key, &p);

    unsigned char md_value[EVP_MAX_MD_SIZE];
    uint32_t md_len;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
    const EVP_MD* md = EVP_sha256();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, buf, len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    assert(md_len == SHA256_DIGEST_SIZE);
    EVP_MD_CTX_destroy(mdctx);
    memcpy(hash, md_value, SHA256_DIGEST_SIZE);
}

static void
openssl_create_key_and_x509
(
    uint8_t* der_key,
    int* der_key_len,
    uint8_t* der_cert,
    int* der_cert_len,
    const struct ra_tls_options* opts
)
{
    /* Generate key. */
    RSA* key;

    static const int nr_bits = 3072;
    key = RSA_generate_key(nr_bits, RSA_F4, NULL, NULL);
    assert(NULL != key);
    
    uint8_t der[4096];
    int derSz = i2d_RSAPrivateKey(key, NULL);
    assert(derSz >= 0);
    assert(derSz <= (int) *der_key_len);
    unsigned char* p = der;
    i2d_RSAPrivateKey(key, &p);

    *der_key_len = derSz;
    memcpy(der_key, der, derSz);

    /* Generate certificate */
    sgx_report_data_t report_data = {0, };
    sha256_rsa_pubkey(report_data.d, key);
    attestation_verification_report_t attestation_report;

    do_remote_attestation(&report_data, opts, &attestation_report);

    EVP_PKEY* evp_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_key, key);
    generate_x509(evp_key, der_cert, der_cert_len,
                  &attestation_report);
    EVP_PKEY_free(evp_key);
    evp_key = NULL;
}

void create_key_and_x509
(
    uint8_t* der_key,  /* out */
    int* der_key_len,  /* in/out */
    uint8_t* der_cert, /* out */
    int* der_cert_len, /* in/out */
    const struct ra_tls_options* opts /* in */
)
{
    openssl_create_key_and_x509(der_key, der_key_len,
                                der_cert, der_cert_len,
                                opts);
}
