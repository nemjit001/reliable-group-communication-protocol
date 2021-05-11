#include "rgcp.h"

#include "systems_headers.h"
#include "linklist.h"

#define RGCP_MIDDLEWARE_TIMEOUT 300000

LIST_HEAD(rgcp_groupfd_list);

struct rgcp_socket
{
    struct list_head list;
    int sockfd;
    int middlewarefd;
    int has_data;

    pthread_mutex_t socket_mtx;
    pthread_t middleware_handler_thread_id;
};

int rgcp_send_middleware_packet(struct rgcp_socket *sock, struct rgcp_packet *packet)
{
    ssize_t bytes_sent = send(sock->middlewarefd, (uint8_t *)packet, sizeof(*packet), 0);

    if (bytes_sent < 0)
    {
        perror("Error sending to middleware");
        return -1;
    }

    if (bytes_sent == 0)
        return 0;

    return bytes_sent;
}

int rgcp_recv_middleware_packet(struct rgcp_socket *sock, struct rgcp_packet *packet)
{
    uint8_t buffer[sizeof(*packet)];
    memset(buffer, 0, sizeof(buffer));

    ssize_t bytes_received = recv(sock->middlewarefd, buffer, sizeof(buffer), 0);

    if (bytes_received < 0)
    {
        perror("Error receiving from middleware");
        return -1;
    }

    if (bytes_received == 0)
        return 0;

    memcpy(packet, buffer, bytes_received);

    return bytes_received;
}

void thread_registersignals(int *sfd)
{
    sigset_t mask;

    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
    {
        perror("Blocking signals failed");
        abort();
    }

    *sfd = signalfd(-1, &mask, 0);
}

int execute_middleware_request(struct rgcp_socket *sock, struct rgcp_packet *packet)
{
    switch(packet->type)
    {
        case RGCP_GROUP_DISCOVER_RESPONSE:
            break;
        case RGCP_NEW_GROUP_MEMBER:
            break;
        case RGCP_DELETE_GROUP_MEMBER:
            break;
        default:
            break;
    }

    return 0;
}

int handle_middleware_requests(struct rgcp_socket *sock)
{
    struct rgcp_packet packet;
    if (rgcp_recv_middleware_packet(sock, &packet) < 0)
        return -1;
    
    return execute_middleware_request(sock, &packet);
}

void *middleware_handler_thread(void *arg)
{
    struct rgcp_socket *sock = (struct rgcp_socket *)arg;

    ssize_t s;
    struct signalfd_siginfo fdsi;
    int sfd = -1;
    thread_registersignals(&sfd);

    if (sfd < 0)
    {
        perror("Creating sfd failed");
        abort();
    }

    printf("[LIB] mw thread start for sock %d\n", sock->sockfd);

    for (;;)
    {
        s = read(sfd, &fdsi, sizeof(fdsi));
        if (s != sizeof(fdsi))
        {
            perror("Reading signal info failed");
            abort();
        }

        if (fdsi.ssi_signo == SIGALRM)
        {
            break;
        }
        else 
        {
            printf("Read unexpected signal 0x%x\n", fdsi.ssi_signo);
            abort();
        }

        // handle incoming middleware requests here
        if (handle_middleware_requests(sock) < 0)
        {
            //TODO: set socket in error state
        }
    }

    printf("[LIB] mw thread stopped\n");
    return NULL;
}

int rgcp_get_next_socket_fd()
{
    if (list_empty(&rgcp_groupfd_list))
        return 1;

    int max_fd = -1;
    struct list_head *current, *next;
    list_for_each_safe(current, next, &rgcp_groupfd_list)
    {
        struct rgcp_socket *entry = list_entry(current, struct rgcp_socket, list);

        max_fd = max_fd > entry->sockfd ? max_fd : entry->sockfd;
    }

    return max_fd + 1;
}

struct rgcp_socket *rgcp_find_by_fd(int sockfd)
{
    // cannot search an empty list or search for an invalid socket value
    if (list_empty(&rgcp_groupfd_list) && sockfd > 0)
        return NULL;

    struct list_head *current, *next;
    list_for_each_safe(current, next, &rgcp_groupfd_list)
    {
        struct rgcp_socket *entry = list_entry(current, struct rgcp_socket, list);
        
        if (entry->sockfd == sockfd)
            return entry;
    }

    return NULL;
}

int wait_with_interupt(int *interupt_signal, useconds_t timeout)
{
    useconds_t tick = 0;
    while(tick < timeout)
    {
        if (*interupt_signal == 1)
            break;

        tick += 10;
        usleep(10);
    }

    return (*interupt_signal == 1);
}

void rgcp_socket_init(int fd, struct rgcp_socket **sock)
{
    pthread_t thread_id;

    (*sock) = calloc(sizeof(struct rgcp_socket), 1);
    (*sock)->sockfd = rgcp_get_next_socket_fd();
    (*sock)->middlewarefd = fd;
    (*sock)->has_data = 0;

    pthread_mutex_init(&(*sock)->socket_mtx, NULL);
    pthread_create(&thread_id, NULL, middleware_handler_thread, *sock);
    (*sock)->middleware_handler_thread_id = thread_id;

    list_add(&(*sock)->list, &rgcp_groupfd_list);
}

void rgcp_socket_free(struct rgcp_socket *sock)
{
    if (sock == NULL)
        return;

    close(sock->middlewarefd);
    pthread_kill(sock->middleware_handler_thread_id, SIGALRM);
    pthread_join(sock->middleware_handler_thread_id, NULL);

    list_del(&sock->list);
    free(sock);
}

int rgcp_socket(int domain, struct sockaddr_in *middleware_addr)
{
    if (domain != AF_INET && domain != AF_INET6)
    {
        errno = EPROTOTYPE;
        return -1;
    }

    if (middleware_addr == NULL)
    {
        errno = EDESTADDRREQ;
        return -1;
    }

    struct rgcp_socket *sock;
    int fd = socket(domain, SOCK_STREAM, IPPROTO_TCP);

    if (fd < 0)
        goto error;

    rgcp_socket_init(fd, &sock);

    // TODO: add host resolve here -> check if address is indeed valid + check if it resolves to valid ipv4/ipv6 host

    if (connect(sock->middlewarefd, (struct sockaddr *) middleware_addr, sizeof(*middleware_addr)) < 0)
        goto error;

    return sock->sockfd;

error:
    rgcp_socket_free(sock);

    return -1;
}

int rgcp_get_group_info(int sockfd, struct rgcp_group_info **groups, size_t *len)
{
    struct rgcp_socket *sock = rgcp_find_by_fd(sockfd);

    if (sock == NULL)
    {
        errno = ENOTSOCK;
        return -1;
    }

    struct rgcp_packet packet;

    // TODO: add extra info here when packet struct is complete
    packet.type = RGCP_GROUP_DISCOVER;

    if (rgcp_send_middleware_packet(sock, &packet) <= 0)
        return -1;

    // FIXME: wait for response interupt or timeout
    if (wait_with_interupt(&sock->has_data, RGCP_MIDDLEWARE_TIMEOUT) == 1)
    {
        sock->has_data = 0;
        // we received response
        // TODO: parse it
    }
    else
    {
        // timeout reached return error
        errno = ETIMEDOUT;
        return -1;
    }

    return 0;
}

int rgcp_create_group(int sockfd, const char *groupname)
{
    struct rgcp_socket *sock = rgcp_find_by_fd(sockfd);

    if (sock == NULL)
    {
        errno = ENOTSOCK;
        return -1;
    }

    struct rgcp_packet packet;

    // TODO: add extra info here when packet struct is complete
    packet.type = RGCP_CREATE_GROUP;

    if (rgcp_send_middleware_packet(sock, &packet) <= 0)
        return -1;

    errno = ENOTSUP;
    return -1;
}

int rgcp_connect(int sockfd, struct rgcp_group_info rgcp_group)
{
    struct rgcp_socket *sock = rgcp_find_by_fd(sockfd);

    if (sock == NULL)
    {
        errno = ENOTSOCK;
        return -1;
    }

    struct rgcp_packet packet;

    // TODO: add extra info here when packet struct is complete
    packet.type = RGCP_JOIN_GROUP;

    if (rgcp_send_middleware_packet(sock, &packet) <= 0)
        return -1;

    errno = ENOTSUP;
    return -1;
}

int rgcp_close(int sockfd)
{
    struct rgcp_socket *sock = rgcp_find_by_fd(sockfd);

    if (sock == NULL)
    {
        errno = ENOTSOCK;
        return -1;
    }

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
