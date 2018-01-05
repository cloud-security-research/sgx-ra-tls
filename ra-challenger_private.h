#include <stdint.h>
#include <stddef.h>

extern const uint8_t ias_response_body_oid[];
extern const uint8_t ias_root_cert_oid[];
extern const uint8_t ias_leaf_cert_oid[];
extern const uint8_t ias_report_signature_oid[];

extern const size_t ias_oid_len;

void find_oid
(
     const unsigned char* ext, size_t ext_len,
     const unsigned char* oid, size_t oid_len,
     unsigned char** val, size_t* len
);
