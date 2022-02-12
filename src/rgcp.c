#include "rgcp.h"

#include "details/rgcp_socket.h"

int rgcp_socket(__attribute__((unused)) int domain, __attribute__((unused)) struct sockaddr* middlewareAddr, __attribute__((unused)) socklen_t* addrlen)
{
    return -1;
}

int rgcp_close(__attribute__((unused)) int sockfd)
{
    return -1;
}
