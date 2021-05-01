#include "rgcp.h"
#include "systems_headers.h"
#include "linklist.h"

LIST_HEAD(rgcp_groupfd_list);

struct rgcp_group_socket
{
    struct list_head list;
    int sockfd;
};

struct rgcp_packet
{
    //
} __attribute__((packed));

struct rgcp_group_socket *rgcp_find_by_fd(int sockfd)
{
    // cannot search an empty list or search for an invalid socket value
    if (list_empty(&rgcp_groupfd_list) && sockfd > 0)
        return NULL;

    struct list_head *current, *next;
    list_for_each_safe(current, next, &rgcp_groupfd_list)
    {
        struct rgcp_group_socket *entry = list_entry(current, struct rgcp_group_socket, list);
        
        if (entry->sockfd == sockfd)
            return entry;
    }

    return NULL;
}

void rgcp_socket_init(int fd, struct rgcp_group_socket **sock)
{
    (*sock) = calloc(sizeof(struct rgcp_group_socket), 1);
    (*sock)->sockfd = fd;
    list_add(&(*sock)->list, &rgcp_groupfd_list);
}

void rgcp_socket_free(struct rgcp_group_socket *sock)
{
    if (sock == NULL)
        return;

    close(sock->sockfd);
    list_del(&sock->list);
    free(sock);
}

int rgcp_socket(int domain)
{
    if (domain != AF_INET && domain != AF_INET6)
        return -1; // TODO: add error code here

    struct rgcp_group_socket *sock;
    int fd = socket(domain, SOCK_STREAM, IPPROTO_TCP);

    if (fd < 0)
        goto error;

    rgcp_socket_init(fd, &sock);

    return sock->sockfd;

error:
    rgcp_socket_free(sock);

    return -1; // TODO: add error codes that mean something
}

int rgcp_connect(int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
    return -1;
}

int rgcp_close(int sockfd)
{
    int success = 1;
    struct rgcp_group_socket *sock = rgcp_find_by_fd(sockfd);

    if (sock == NULL)
        return -1; // TODO: add error code here

    rgcp_socket_free(sock);

    return success ? 0 : -1; // TODO: add error code here
}

ssize_t rgcp_send(int sockfd, const void *buf, size_t len, int flags)
{
    return -1;
}

ssize_t rgcp_recv(int sockfd, void *buf, size_t len, int flags)
{
    return -1;
}
