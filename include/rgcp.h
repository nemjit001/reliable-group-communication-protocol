#ifndef RGCP_H
#define RGCP_H

#include <sys/socket.h>

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

int rgcp_socket(int domain, struct sockaddr* middlewareAddr, socklen_t* addrlen);

int rgcp_close(int sockfd);

int rgcp_discover_groups(int sockfd);

int rgcp_create_group(int sockfd, const char* groupname);

int rgcp_connect(int sockfd);

int rgcp_disconnect(int sockfd);

ssize_t rgcp_send(int sockfd, const char* buf, size_t len, enum RGCP_SEND_FLAGS flags);

ssize_t rgcp_recv(int sockfd);

#endif // RGCP_H
