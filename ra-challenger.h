#ifndef _RA_CHALLENGER_H_
#define _RA_CHALLENGER_H_

#include <sgx_quote.h>

void get_quote_from_report
(
    const uint8_t* report /* in */,
    const int report_len  /* in */,
    sgx_quote_t* quote
);

void get_quote_from_cert
(
    const uint8_t* der_crt,
    uint32_t der_crt_len,
    sgx_quote_t* q
);

int verify_sgx_cert_extensions
(
    uint8_t* der_crt,
    uint32_t der_crt_len
);

#endif
