#include "rgcp.h"

#include "systems_headers.h"
#include "linklist.h"

#define RGCP_MIDDLEWARE_TIMEOUT 3000000

#define max(a,b) (a > b ? a : b)

LIST_HEAD(rgcp_groupfd_list);

struct rgcp_socket
{
    struct list_head list;
    int sockfd;
    int middlewarefd;

    int connected_to_group;
    int received_response;

    pthread_mutex_t socket_mtx;
    pthread_t middleware_handler_thread_id;
};

int rgcp_pack(enum rgcp_request_type type, union rgcp_packet_data *data, struct rgcp_packet **packet)
{
    *packet = calloc(sizeof(struct rgcp_packet), 1);

    (*packet)->packet_len = sizeof(**packet);
    (*packet)->type = type;

    if (type == RGCP_GROUP_DISCOVER)
    {
        // nothing needs to be set
    }
    else if (type == RGCP_CREATE_GROUP)
    {
        (*packet)->packet_len +=
            sizeof(data->group_info.name_length) + 
            sizeof(data->group_info.peer_count) +
            ( data->group_info.name_length * sizeof(char) ) +
            ( data->group_info.peer_count * sizeof(struct rgcp_peer_info) );
        
        (*packet) = realloc((*packet), (*packet)->packet_len);

        uint32_t offset = 0;
        memcpy((*packet)->data, &data->group_info.name_length, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        memcpy((*packet)->data + offset, data->group_info.group_name, data->group_info.name_length * sizeof(char));
        offset += data->group_info.name_length;
        memcpy((*packet)->data + offset, &data->group_info.peer_count, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        memcpy((*packet)->data + offset, data->group_info.peers, data->group_info.peer_count * sizeof(struct rgcp_peer_info));
    }

    return 0;
}

int rgcp_send_middleware_packet(struct rgcp_socket *sock, enum rgcp_request_type type, union rgcp_packet_data *data)
{
    struct rgcp_packet *packet = NULL;

    if (rgcp_pack(type, data, &packet) < 0)
    {
        fprintf(stderr, "[LIB] error serializing packet\n");
        return -1;
    }

    ssize_t bytes_sent = send(sock->middlewarefd, (uint8_t *)packet, packet->packet_len, 0);

    if (bytes_sent < 0)
    {
        perror("Error sending to middleware");
        free(packet);
        return -1;
    }

    free(packet);

    return bytes_sent;
}

int rgcp_recv_middleware_packet(struct rgcp_socket *sock, struct rgcp_packet **packet)
{
    uint8_t size_buffer[sizeof(uint32_t)];
    int res1 = recv(sock->middlewarefd, size_buffer, sizeof(size_buffer), 0);

    if (res1 <= 0)
        return -1;

    uint32_t packet_length = 0;

    for (size_t i = 0; i < sizeof(uint32_t); i++)
        packet_length += (uint8_t)(size_buffer[i] >> (sizeof(uint8_t) - 1 - i));

    printf("%d\n", packet_length);

    if (packet_length == 0)
        return -1;

    uint8_t data_buffer[packet_length - sizeof(uint32_t)];
    int res2 = recv(sock->middlewarefd, data_buffer, packet_length - sizeof(uint32_t), 0);

    if (res2 < 0)
        return -1;

    uint8_t packet_buffer[packet_length];

    memcpy(packet_buffer, size_buffer, sizeof(uint32_t));
    memcpy(packet_buffer + sizeof(uint32_t), data_buffer, packet_length - sizeof(uint32_t));

    *packet = calloc(packet_length, 1);
    memcpy(*packet, packet_buffer, packet_length);

    return res1 + res2;
}

void thread_register_signals(int *sfd)
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
    pthread_mutex_lock(&sock->socket_mtx);

    sock->received_response = 1;

    // TODO: send data to other thread
    // internal sockets?

    pthread_mutex_unlock(&sock->socket_mtx);

    return 0;
}

int handle_middleware_requests(struct rgcp_socket *sock)
{
    struct rgcp_packet *packet = NULL;
    if (rgcp_recv_middleware_packet(sock, &packet) < 0)
        return -1;
    
    int retval = execute_middleware_request(sock, packet);
    free(packet);
    return retval;
}

void *middleware_handler_thread(void *arg)
{
    struct rgcp_socket *sock = (struct rgcp_socket *)arg;

    ssize_t s;
    struct signalfd_siginfo fdsi;
    int sfd = -1;
    fd_set read_fds;

    thread_register_signals(&sfd);

    if (sfd < 0)
    {
        perror("Creating sfd failed");
        abort();
    }

    printf("[LIB] mw thread start for sock %d\n", sock->sockfd);

    for (;;)
    {
        FD_ZERO(&read_fds);
        FD_SET(sfd, &read_fds);
        FD_SET(sock->middlewarefd, &read_fds);

        if (select(max(sock->middlewarefd, sfd) + 1, &read_fds, NULL, NULL, NULL) < 0)
        {
            perror("Select failed");
            abort();
        }

        if (FD_ISSET(sfd, &read_fds))
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
        }

        if (FD_ISSET(sock->middlewarefd, &read_fds))
        {
            // handle incoming middleware requests here
            if (handle_middleware_requests(sock) < 0)
            {
                //TODO: set socket in error state
            }
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
    (*sock)->connected_to_group = 0;
    (*sock)->received_response = 0;

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

int rgcp_get_group_info(int sockfd, __attribute__((unused)) struct rgcp_group_info **groups, __attribute__((unused)) size_t *len)
{
    struct rgcp_socket *sock = rgcp_find_by_fd(sockfd);

    if (sock == NULL)
    {
        errno = ENOTSOCK;
        return -1;
    }

    if (rgcp_send_middleware_packet(sock, RGCP_GROUP_DISCOVER, NULL) <= 0)
        return -1;

    // FIXME: wait for response interupt or timeout
    if (wait_with_interupt(&sock->received_response, RGCP_MIDDLEWARE_TIMEOUT) == 1)
    {
        pthread_mutex_lock(&sock->socket_mtx);
        sock->received_response = 0;
        // we received response
        // TODO: parse it

        pthread_mutex_unlock(&sock->socket_mtx);
    }
    else
    {
        // timeout reached return error
        errno = ETIMEDOUT;
        return -1;
    }

    return 0;
}

int rgcp_create_group(int sockfd, __attribute__((unused)) const char *groupname)
{
    struct rgcp_socket *sock = rgcp_find_by_fd(sockfd);

    if (sock == NULL)
    {
        errno = ENOTSOCK;
        return -1;
    }

    union rgcp_packet_data data;
    memset(&data, 0, sizeof(data));
    
    data.group_info.name_length = strlen(groupname) + 1; // +1 accounts for NULL byte
    data.group_info.group_name = calloc(data.group_info.name_length, sizeof(char));
    memcpy(data.group_info.group_name, groupname, data.group_info.name_length);
    data.group_info.peer_count = 0;
    data.group_info.peers = NULL;

    if (rgcp_send_middleware_packet(sock, RGCP_CREATE_GROUP, &data) <= 0)
        return -1;

    // peer info is not alloc'd, so no free
    free(data.group_info.group_name);

    errno = ENOTSUP;
    return -1;
}

int rgcp_connect(int sockfd, __attribute__((unused)) struct rgcp_group_info rgcp_group)
{
    struct rgcp_socket *sock = rgcp_find_by_fd(sockfd);

    if (sock == NULL)
    {
        errno = ENOTSOCK;
        return -1;
    }

    union rgcp_packet_data data;
    memset(&data, 0, sizeof(data));
    // TODO: fill out data

    if (rgcp_send_middleware_packet(sock, RGCP_JOIN_GROUP, &data) <= 0)
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

ssize_t rgcp_send(__attribute__((unused)) int sockfd, __attribute__((unused)) const void *buf, __attribute__((unused)) size_t len, __attribute__((unused)) int flags)
{
    errno = ENOTSUP;
    return -1;
}

ssize_t rgcp_recv(__attribute__((unused)) int sockfd, __attribute__((unused)) void *buf, __attribute__((unused)) size_t len, __attribute__((unused)) int flags)
{
    errno = ENOTSUP;
    return -1;
}
