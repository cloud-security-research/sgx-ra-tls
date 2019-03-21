#ifndef __ECDSA_RA_ATTESTER__
#define __ECDSA_RA_ATTESTER__

int connect_to_quote_service(void);
    
void get_quote_from_quote_service
(
    int sockfd,
    const sgx_report_t* report,
    uint8_t* quote,
    uint32_t quote_len
);

void get_target_info_from_quote_service
(
    int sockfd,
    sgx_target_info_t* target_info,
    uint32_t* quote_size
);

#endif
