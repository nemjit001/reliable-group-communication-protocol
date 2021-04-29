#include "rgcp.h"

int rgcp_group_connect(int sockfd, struct sockaddr* addr, socklen_t addrlen)
{
    return -1;
}

int rgcp_remote_connect(int sockfd, struct sockaddr* addr, socklen_t addrlen)
{
    return -1;
}

int rgcp_close(int sockfd)
{
    return -1;
}

ssize_t rgcp_send(int sockfd, const void *buf, size_t len, int flags)
{
    return -1;
}

ssize_t rgcp_recv(int sockfd, void *buf, size_t len, int flags)
{
    return -1;
}

int rgcp_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    return -1;
}

int rgcp_listen(int sockfd, int backlog)
{
    return -1;
}

int rgcp_accept(int sockfd, struct sockaddr* addr, socklen_t * addrlen)
{
    return -1;
}
