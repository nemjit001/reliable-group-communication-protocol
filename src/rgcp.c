#include "rgcp.h"

int rgcp_v4_connect(struct rgcp_sock *sk, struct sockaddr* addr, socklen_t addrlen, int flags)
{
    return -1;
}

int rgcp_v4_close(struct rgcp_sock *sk)
{
    return -1;
}

ssize_t rgcp_v4_send(struct rgcp_sock *sk, const void *buf, size_t len, int flags)
{
    return -1;
}

ssize_t rgcp_v4_recv(struct rgcp_sock *sk, void *buf, size_t len, int flags)
{
    return -1;
}

int rgcp_v4_bind(struct rgcp_sock *sk, const struct sockaddr *addr, socklen_t addrlen)
{
    return -1;
}

int rgcp_v4_listen(struct rgcp_sock *sk, int backlog)
{
    return -1;
}

int rgcp_v4_accept(struct rgcp_sock *sk, struct sockaddr* addr, socklen_t* addrlen)
{
    return -1;
}
