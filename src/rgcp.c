#include "rgcp.h"
#include "systems_headers.h"
#include "linklist.h"

LIST_HEAD(rgcp_groupfd_list);

struct rgcp_packet_buffer_entry
{
    struct list_head list;
    struct rgcp_packet packet;
};

enum rgcp_group_socket_state
{
    RGCP_SOCK_CONNECTED,
    RGCP_SOCK_CONNECTING,
    RGCP_SOCK_CLOSING,
    RGCP_SOCK_CLOSED
};

struct rgcp_group_socket
{
    struct list_head list;
    int sockfd;
    int middlewarefd;
    int peer_count;
    int *peerfds;

    int last_packet_id;
    enum rgcp_group_socket_state socket_state;
    pthread_t receive_thread_id;
    struct list_head packet_buffer;
};

int rgcp_middleware_handler(struct rgcp_group_socket *sock)
{
    if (sock->socket_state == RGCP_SOCK_CLOSED)
    {
        // TODO: remove print calls
        printf("[LIB] rgcp sock closed\n");
        return -1;
    }

    char buffer[RGCP_MAX_PACKET_LENGTH];
    memset(&buffer, 0, sizeof(buffer));

    if (recv(sock->middlewarefd, buffer, sizeof(buffer), 0) < 0)
    {
        perror("Receive from middleware failed");
        sock->socket_state = RGCP_SOCK_CLOSED;
        return -1;
    }

    struct rgcp_packet *packet = (struct rgcp_packet *)buffer;
    printf("[LIB]\t [PACKET RECV ( %u )] : %u | %u, %lu\n", sock->sockfd, packet->id, packet->type, packet->data_length);

    switch (packet->type)
    {
    case RGCP_CONNECT_OK:
        break;
    case RGCP_MAX_CLIENTS:
        break;
    case RGCP_GROUP_DISCOVERY_RESPONSE:
        break;
    case RGCP_GROUP_DISCONNECT_OK:
        break;
    case RGCP_DISCONNECT_OK:
        break;
    case RGCP_KEEPALIVE:
        // ping back
        break;
    default:
        printf("[LIB]\t [UNKNOWN PACKET RECV ( %u )] : %u | %u, %lu\n", sock->sockfd, packet->id, packet->type, packet->data_length);
        break;
    }

    return 0;
}

void *rgcp_middleware_handler_thread(void *arg)
{
    // TODO: remove print calls
    printf("[LIB] Starting handler thread\n");

    struct rgcp_group_socket *sock = (struct rgcp_group_socket *)arg;
    while(rgcp_middleware_handler(sock) == 0);
}

int rgcp_get_next_socket_fd()
{
    if (list_empty(&rgcp_groupfd_list))
        return 1;

    int max_fd = -1;
    struct list_head *current, *next;
    list_for_each_safe(current, next, &rgcp_groupfd_list)
    {
        struct rgcp_group_socket *entry = list_entry(current, struct rgcp_group_socket, list);

        max_fd = max_fd > entry->sockfd ? max_fd : entry->sockfd;
    }

    return max_fd + 1;
}

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
    (*sock)->sockfd = rgcp_get_next_socket_fd();
    (*sock)->middlewarefd = fd;
    (*sock)->peer_count = 0;
    (*sock)->peerfds = calloc(0, sizeof(int));
    
    (*sock)->last_packet_id = 0;
    (*sock)->socket_state = RGCP_SOCK_CLOSED;
    (*sock)->receive_thread_id = -1;

    // initialize packet buffer to allow rebuilding fragmented packets
    list_init(&(*sock)->packet_buffer);

    list_add(&(*sock)->list, &rgcp_groupfd_list);
}

void rgcp_socket_free(struct rgcp_group_socket *sock)
{
    if (sock == NULL)
        return;

    close(sock->middlewarefd);

    for (int i = 0; i < sock->peer_count; i++)
    {
        close(sock->peerfds[i]);
    }

    free(sock->peerfds);

    list_del(&sock->list);
    free(sock);
}

int send_connect_signal(struct rgcp_group_socket *sock)
{
    struct rgcp_packet packet;

    memset(&packet, 0, sizeof(packet));
    packet.type = RGCP_CONNECT;
    packet.data_length = 0;

    if (send(sock->middlewarefd, (uint8_t *) & packet, sizeof(packet), 0) < 0)
    {
        perror("Sending connect signal failed");
        return -1;
    }

    return 0;
}

int send_disconnect_signal(struct rgcp_group_socket *sock)
{
    struct rgcp_packet packet;

    memset(&packet, 0, sizeof(packet));
    packet.type = RGCP_DISCONNECT;
    packet.data_length = 0;

    if (send(sock->middlewarefd, (uint8_t *) & packet, sizeof(packet), 0) < 0)
    {
        perror("Sending disconnect signal failed");
        return -1;
    }

    return 0;
}

int rgcp_socket(int domain, const char *middleware_hostname)
{
    if (domain != AF_INET && domain != AF_INET6)
    {
        errno = EPROTOTYPE;
        return -1;
    }

    if (middleware_hostname == NULL)
    {
        errno = EDESTADDRREQ;
        return -1;
    }

    struct sockaddr_in addr;
    struct rgcp_group_socket *sock;
    int fd = socket(domain, SOCK_STREAM, IPPROTO_TCP);

    if (fd < 0)
        goto error;

    rgcp_socket_init(fd, &sock);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = domain;
    addr.sin_port = htons(RGCP_MIDDLEWARE_PORT);

    // see https://man7.org/linux/man-pages/man3/inet_pton.3.html
    if (inet_pton(domain, middleware_hostname, & addr.sin_addr.s_addr) != 1)
        return -1;

    // TODO: add host resolve here -> check if address is indeed valid + check if it resolves to valid ipv4/ipv6 host

    if (connect(sock->middlewarefd, (struct sockaddr *) & addr, sizeof(addr)) < 0)
        return -1;

    // socket is now in connecting state
    sock->socket_state = RGCP_SOCK_CONNECTING;

    pthread_create(&sock->receive_thread_id, NULL, rgcp_middleware_handler_thread, sock);

    if (send_connect_signal(sock) < 0)
        goto error;

    // after timeout + middleware handler -> is connected, could also be closed if max clients
    // TODO: needs check
    sock->socket_state = RGCP_SOCK_CONNECTED;

    return sock->sockfd;

error:
    rgcp_socket_free(sock);

    return -1;
}

int rgcp_get_group_info(struct rgcp_group_info **groups, size_t *len)
{
    errno = ENOTSUP;
    return -1;
}

int rgcp_connect(int sockfd, struct rgcp_group_info rgcp_group)
{
    errno = ENOTSUP;
    return -1;
}

int rgcp_close(int sockfd)
{
    struct rgcp_group_socket *sock = rgcp_find_by_fd(sockfd);

    if (sock == NULL)
    {
        errno = ENOTSOCK;
        return -1;
    }

    sock->socket_state = RGCP_SOCK_CLOSING;

    send_disconnect_signal(sock);

    // TODO: add signal handler if disconnect is acked -> then we can join thread
    // some kind of timeout? for now just set to closed
    sock->socket_state = RGCP_SOCK_CLOSED;

    pthread_join(sock->receive_thread_id, NULL);

    rgcp_socket_free(sock);

    return 0;
}

ssize_t rgcp_send(int sockfd, const void *buf, size_t len, int flags)
{
    errno = ENOTSUP;
    return -1;
}

ssize_t rgcp_recv(int sockfd, void *buf, size_t len, int flags)
{
    errno = ENOTSUP;
    return -1;
}
