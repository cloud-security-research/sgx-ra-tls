#include <assert.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "sgx_report.h"
#include "ecdsa-aesmd-messages.pb-c.h"

#include "ra-attester_private.h"

/**
 * Establish connection to Quote Service.
 */
int connect_to_quote_service(void)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(-1 != sockfd);
    struct sockaddr_in srvaddr = {0, };
    srvaddr.sin_family = AF_INET;
    srvaddr.sin_port = htons(12345);
    inet_pton(AF_INET, "127.0.0.1", &srvaddr.sin_addr);
    int rc = connect(sockfd, (struct sockaddr*) &srvaddr, sizeof(srvaddr));
    assert(-1 != rc);
    return sockfd;
}

/**
 * Low-level socket I/O to obtain quoting enclave's target info and
 * quote size.
 */
void get_target_info_from_quote_service
(
    int sockfd,
    sgx_target_info_t* target_info,
    uint32_t* quote_size
)
{
    Quoteservice__Message__Request__InitQuoteRequest request =
        QUOTESERVICE__MESSAGE__REQUEST__INIT_QUOTE_REQUEST__INIT;
    Quoteservice__Message__Request wrapper_msg =
        QUOTESERVICE__MESSAGE__REQUEST__INIT;
    wrapper_msg.initquoterequest = &request;
    uint32_t payload_len = quoteservice__message__request__get_packed_size(&wrapper_msg);
    uint32_t total_len = payload_len + sizeof(payload_len);
    uint8_t buf[1024];
    assert(total_len <= sizeof(buf));
    memcpy(buf, (uint8_t*) &payload_len, sizeof(payload_len));
    quoteservice__message__request__pack(&wrapper_msg, buf + sizeof(payload_len));
    int rc = send(sockfd, buf, total_len, 0);
    assert(rc == (int) total_len);

    rc = recv(sockfd, (uint8_t*) &payload_len, sizeof(payload_len), 0);
    assert(rc == sizeof(payload_len));
    assert(payload_len <= sizeof(buf));
    rc = recv(sockfd, buf, payload_len, 0);
    assert(rc == (int) payload_len);
    Quoteservice__Message__Response* msg =
        quoteservice__message__response__unpack(NULL, payload_len, buf);
    assert(NULL != msg->initquoteresponse);
    Quoteservice__Message__Response__InitQuoteResponse* response =
        msg->initquoteresponse;
    assert(response->has_targetinfo);
    assert(response->targetinfo.len == sizeof(*target_info));
    memcpy(target_info, response->targetinfo.data, response->targetinfo.len);
    *quote_size = response->quote_size;
}

/**
 * Low-level socket I/O with "Quote Service" to obtain quote based on report.
 */
void get_quote_from_quote_service
(
    int sockfd,
    const sgx_report_t* report,
    uint8_t* quote,
    uint32_t quote_len
)
{
    Quoteservice__Message__Request__GetQuoteRequest request =
        QUOTESERVICE__MESSAGE__REQUEST__GET_QUOTE_REQUEST__INIT;
    Quoteservice__Message__Request wrapper_msg =
        QUOTESERVICE__MESSAGE__REQUEST__INIT;
    wrapper_msg.getquoterequest = &request;
    request.report.data = (uint8_t*) report;
    request.report.len = sizeof(*report);

    /* print_byte_array(stdout, (uint8_t*) report, sizeof(*report)); */
    /* printf("\n"); */
    
    uint32_t payload_len = quoteservice__message__request__get_packed_size(&wrapper_msg);
    uint32_t total_len = payload_len + sizeof(payload_len);
    uint8_t buf[4096];
    assert(total_len <= sizeof(buf));
    memcpy(buf, (uint8_t*) &payload_len, sizeof(payload_len));
    quoteservice__message__request__pack(&wrapper_msg, buf + sizeof(payload_len));
    int rc = send(sockfd, buf, total_len, 0);
    assert(rc == (int) total_len);

    rc = recv(sockfd, (uint8_t*) &payload_len, sizeof(payload_len), 0);
    assert(rc == sizeof(payload_len));
    assert(payload_len <= sizeof(buf));
    rc = recv(sockfd, buf, payload_len, 0);
    assert(rc == (int) payload_len);
    Quoteservice__Message__Response* msg =
        quoteservice__message__response__unpack(NULL, payload_len, buf);
    assert(NULL != msg->getquoteresponse);
    Quoteservice__Message__Response__GetQuoteResponse* response =
        msg->getquoteresponse;
    assert(response->has_quote);
    assert(response->quote.len == quote_len);
    memcpy(quote, response->quote.data, response->quote.len);
}
