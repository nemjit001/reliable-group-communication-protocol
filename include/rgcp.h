#ifndef RGCP_H
#define RGCP_H

#include "details/rgcp_group.h"

#include <arpa/inet.h>

#ifndef RGCP_SOCKET_TIMEOUT_MS
    #define RGCP_SOCKET_TIMEOUT_MS 10000
#endif

#ifndef RGCP_SOCKET_HEARTBEAT_PERIOD_SECONDS
    #define RGCP_SOCKET_HEARTBEAT_PERIOD_SECONDS 30
#endif

enum RGCP_SEND_FLAGS
{
    RGCP_SEND_BROADCAST = 1
};

typedef struct _rgcp_recv_data_t
{
    int m_sourceFd;
    size_t m_bufferSize;
    uint8_t* m_pDataBuffer;
} rgcp_recv_data_t;

int rgcp_socket(int domain, struct sockaddr* middlewareaddr, socklen_t addrlen);

int rgcp_close(int sockfd);

ssize_t rgcp_discover_groups(int sockfd, rgcp_group_t** pp_groups);

int rgcp_create_group(int sockfd, const char* groupname, size_t namelen);

int rgcp_connect(int sockfd, rgcp_group_t group);

int rgcp_disconnect(int sockfd);

ssize_t rgcp_send(int sockfd, const char* buf, size_t len, enum RGCP_SEND_FLAGS flags);

ssize_t rgcp_recv(int sockfd, rgcp_recv_data_t** pp_recvdatalist);

#endif // RGCP_H
