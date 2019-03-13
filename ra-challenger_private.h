#include <stdint.h>
#include <stddef.h>

extern const uint8_t ias_response_body_oid[];
extern const uint8_t ias_root_cert_oid[];
extern const uint8_t ias_leaf_cert_oid[];
extern const uint8_t ias_report_signature_oid[];

extern const uint8_t quote_oid[];
extern const uint8_t pck_crt_oid[];
extern const uint8_t pck_sign_chain_oid[];
extern const uint8_t tcb_info_oid[];
extern const uint8_t tcb_sign_chain_oid[];

extern const size_t ias_oid_len;

void find_oid
(
     const unsigned char* ext, size_t ext_len,
     const unsigned char* oid, size_t oid_len,
     unsigned char** val, size_t* len
);

void extract_x509_extensions
(
    uint8_t* ext,
    int ext_len,
    attestation_verification_report_t* attn_report
);

void extract_x509_extension
(
    uint8_t* ext,
    int ext_len,
    const uint8_t* oid,
    size_t oid_len,
    uint8_t* data,
    uint32_t* data_len,
    uint32_t data_max_len
);
