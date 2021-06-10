#include "rgcp.h"

#include "systems_headers.h"
#include "linklist.h"

#define RGCP_MIDDLEWARE_TIMEOUT 10000000

#define max(a,b) (a > b ? a : b)

LIST_HEAD(rgcp_groupfd_list);

struct rgcp_peer
{
    struct list_head list;
    struct sockaddr_in addr;
    socklen_t addrlen;
    int peer_fd;
};

struct rgcp_group_connection_info
{
    char *groupname;
    struct list_head peer_list;
};

struct rgcp_listen_socket_info
{
    struct sockaddr_in addr;
    socklen_t addrlen;
    int listenfd;
};

struct rgcp_socket
{
    struct list_head list;
    int sockfd;
    int middlewarefd;

    int connected_to_group;
    struct rgcp_group_connection_info group_connection_info;
    struct rgcp_listen_socket_info listen_socket_info;

    int received_response;
    int thread_comms_channel[2];

    pthread_mutex_t socket_mtx;
    pthread_t middleware_handler_thread_id;
};

int unpack_group_info_packet(struct rgcp_group_info *info, struct rgcp_packet *packet, uint32_t offset_start)
{
    uint32_t data_length = packet->packet_len - sizeof(struct rgcp_packet);

    if (data_length == 0)
        return -1;

    uint32_t offset = offset_start;

    if (data_length < offset + sizeof(uint32_t))
        return -1;

    memcpy(&info->name_length, packet->data + offset, sizeof(uint32_t));

    offset += sizeof(uint32_t);

    if (data_length < offset + (info->name_length * sizeof(char)))
        return -1;

    info->group_name = calloc(info->name_length, sizeof(char));
    memcpy(info->group_name, packet->data + offset, info->name_length * sizeof(char));

    offset += info->name_length * sizeof(char);

    if (data_length < offset + sizeof(uint32_t))
        return -1;

    memcpy(&info->peer_count, packet->data + offset, sizeof(uint32_t));

    offset += sizeof(uint32_t);

    if (data_length < offset + (info->peer_count * sizeof(struct rgcp_peer_info)))
        return -1;

    info->peers = calloc(info->peer_count, sizeof(struct rgcp_peer_info));
    memcpy(info->peers, packet->data + offset, info->peer_count * sizeof(struct rgcp_peer_info));
    
    offset += info->peer_count * sizeof(struct rgcp_peer_info);

    return offset;
}

int unpack_peer_info_packet(struct rgcp_peer_info *info, struct rgcp_packet *packet, uint32_t offset_start)
{
    uint32_t data_length = packet->packet_len - sizeof(struct rgcp_packet);
    uint32_t offset = offset_start;

    if (data_length == 0 || data_length < sizeof(struct rgcp_peer_info))
        return -1;

    memcpy(&info->addr, packet->data + offset, sizeof(struct sockaddr_in));
    offset += sizeof(struct sockaddr_in);

    memcpy(&info->addrlen, packet->data + offset, sizeof(socklen_t));
    offset += sizeof(socklen_t);

    return offset;
}

int rgcp_unpack(union rgcp_packet_data *data, struct rgcp_packet *packet)
{
    if (packet->type == RGCP_GROUP_DISCOVER_RESPONSE)
    {
        uint32_t offset = 0;
        memcpy(&data->groups.group_count, packet->data, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        data->groups.groups = calloc(data->groups.group_count, sizeof(struct rgcp_group_info));
        
        for (uint32_t i = 0; i < data->groups.group_count; i++)
        {
            struct rgcp_group_info group;
            int res = unpack_group_info_packet(&group, packet, offset);

            if (res < 0)
                return -1;

            offset = res;

            data->groups.groups[i] = group;
        }
    }
    else if (packet->type == RGCP_JOIN_RESPONSE)
    {
        return unpack_group_info_packet(&data->group_info, packet, 0) > 0 ? 0 : -1;
    }
    else if (packet->type == RGCP_NEW_GROUP_MEMBER || packet->type == RGCP_DELETE_GROUP_MEMBER)
    {
        return unpack_peer_info_packet(&data->peer, packet, 0) > 0 ? 0 : -1;
    }
    else
    {
        // invalid type passed
        return -1;
    }

    return 0;
}

int pack_group_info_packet(struct rgcp_group_info *info, uint8_t *array)
{
    uint32_t offset = 0;
    memcpy(array, &info->name_length, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(array + offset, info->group_name, info->name_length * sizeof(char));
    offset += info->name_length * sizeof(char);
    memcpy(array + offset, &info->peer_count, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(array + offset, info->peers, info->peer_count * sizeof(struct rgcp_peer_info));
    offset += info->peer_count * sizeof(struct rgcp_peer_info);
    return offset;
}

int pack_peer_info_packet(struct rgcp_peer_info *info, uint8_t *array)
{
    uint32_t offset = 0;
    memcpy(array + offset, &info->addr, sizeof(struct sockaddr_in));
    offset += sizeof(struct sockaddr_in);

    memcpy(array + offset, &info->addrlen, sizeof(socklen_t));
    offset += sizeof(socklen_t);

    return offset;
}

int rgcp_pack(enum rgcp_request_type type, union rgcp_packet_data *data, struct rgcp_packet **packet)
{
    *packet = calloc(sizeof(struct rgcp_packet), 1);

    (*packet)->packet_len = sizeof(**packet);
    (*packet)->type = type;

    if (type == RGCP_GROUP_DISCOVER)
    {
        // nothing needs to be set
    }
    else if (type == RGCP_CREATE_GROUP || type == RGCP_JOIN_GROUP || type == RGCP_LEAVE_GROUP)
    {
        (*packet)->packet_len +=
            sizeof(data->group_info.name_length) + 
            sizeof(data->group_info.peer_count) +
            ( data->group_info.name_length * sizeof(char) ) +
            ( data->group_info.peer_count * sizeof(struct rgcp_peer_info) );
        
        (*packet) = realloc((*packet), (*packet)->packet_len);

        return pack_group_info_packet(&data->group_info, (*packet)->data) >= 0 ? 0 : -1;
    }
    else if (type == RGCP_ADDRINFO_SHARE)
    {
        (*packet)->packet_len += sizeof(struct rgcp_peer_info);
        
        (*packet) = realloc((*packet), (*packet)->packet_len);

        return pack_peer_info_packet(&data->peer, (*packet)->data) >= 0 ? 0 : -1;
    }
    else
    {
        // invalid type has been passed to pack function, return with error
        return -1;
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

    uint32_t packet_length = *((uint32_t *)size_buffer);

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

int add_group_member(struct rgcp_socket *sock, struct rgcp_packet *packet)
{
    union rgcp_packet_data data;
    memset(&data, 0, sizeof(data));

    if (rgcp_unpack(&data, packet) < 0)
        return -1;

    if (sock->listen_socket_info.listenfd < 0)
        return -1;

    struct sockaddr_in peer_addr;
    socklen_t addrlen = sizeof(peer_addr);
    int remote_fd = accept(sock->listen_socket_info.listenfd, (struct sockaddr *) & peer_addr, &addrlen);

    if (peer_addr.sin_addr.s_addr != data.peer.addr.sin_addr.s_addr)
    {
        printf("error: unexpected peer adress?\n");
        return -1;
    }

    struct rgcp_peer *peer = calloc(sizeof(struct rgcp_peer), 1);

    peer->addr = data.peer.addr;
    peer->addrlen = data.peer.addrlen;
    peer->peer_fd = remote_fd;

    list_add(&peer->list, &sock->group_connection_info.peer_list);

    return 0;
}

int remove_group_member(struct rgcp_socket *sock, struct rgcp_packet *packet)
{
    union rgcp_packet_data data;
    memset(&data, 0, sizeof(data));

    if (rgcp_unpack(&data, packet) < 0)
        return -1;

    struct list_head *current, *next;
    list_for_each_safe(current, next, &sock->group_connection_info.peer_list)
    {
        struct rgcp_peer *entry = list_entry(current, struct rgcp_peer, list);

        if (
            entry->addr.sin_addr.s_addr == data.peer.addr.sin_addr.s_addr &&
            entry->addr.sin_port == data.peer.addr.sin_port &&
            entry->addr.sin_family == data.peer.addr.sin_family
        )
        {
            break;
        }
    }

    struct rgcp_peer *peer = list_entry(current, struct rgcp_peer, list);

    close(peer->peer_fd);
    list_del(&peer->list);

    free(peer);

    return 0;
}

int handle_passive_request(struct rgcp_socket *sock, struct rgcp_packet *packet)
{
    int res = 0;

    switch (packet->type)
    {
    case RGCP_NEW_GROUP_MEMBER:
        res = add_group_member(sock, packet);
        break;
    case RGCP_DELETE_GROUP_MEMBER:
        res = remove_group_member(sock, packet);
        break;
    default:
        break;
    }

    return res < 0 ? -1 : 0;
}

int forward_middleware_request(struct rgcp_socket *sock, struct rgcp_packet *packet)
{
    sock->received_response = 1;
    int res = write(sock->thread_comms_channel[1], (uint8_t *)packet, packet->packet_len);
    return res < 0 ? -1 : 0;
}

int read_from_thread_comms_channel(int fd, struct rgcp_packet **packet)
{
    uint8_t size_buffer[sizeof(uint32_t)];
    int res1 = read(fd, size_buffer, sizeof(uint32_t));

    // If error remote client has exited unexpectedly or closed socket incorrectly
    if (res1 < 0)
        return -1;

    // client closed normally
    if (res1 == 0)
        return 0;

    uint32_t packet_length = *((uint32_t *)size_buffer);

    // erronous packet length received, probably due to client crash
    if (packet_length == 0)
        return -1;

    uint8_t data_buffer[packet_length - sizeof(uint32_t)];
    int res2 = read(fd, data_buffer, packet_length - sizeof(uint32_t));

    // second recv call empty check
    if (res2 < 0)
        return -1;

    uint8_t packet_buffer[packet_length];

    // copying over to relevant pointer offsets
    memcpy(packet_buffer, size_buffer, sizeof(uint32_t));
    memcpy(packet_buffer + sizeof(uint32_t), data_buffer, packet_length - sizeof(uint32_t));

    *packet = calloc(packet_length, 1);
    memcpy(*packet, packet_buffer, packet_length);

    return res1 + res2;
}

int handle_middleware_requests(struct rgcp_socket *sock)
{
    pthread_mutex_lock(&sock->socket_mtx);

    struct rgcp_packet *packet = NULL;
    if (rgcp_recv_middleware_packet(sock, &packet) < 0)
        return -1;
    
    int retval = 0;

    switch(packet->type)
    {
        case RGCP_GROUP_DISCOVER_RESPONSE:
        case RGCP_CREATE_GROUP_OK:
        case RGCP_CREATE_GROUP_ERROR_NAME:
        case RGCP_CREATE_GROUP_ERROR_MAX_GROUPS:
        case RGCP_CREATE_GROUP_ERROR_ALREADY_EXISTS:
        case RGCP_JOIN_RESPONSE:
        case RGCP_JOIN_ERROR_NO_SUCH_GROUP:
        case RGCP_JOIN_ERROR_NAME:
        case RGCP_JOIN_ERROR_MAX_CLIENTS:
        case RGCP_JOIN_ERROR_ALREADY_IN_GROUP:
            // received active response -> forward to main thread
            retval = forward_middleware_request(sock, packet);
            break;
        case RGCP_NEW_GROUP_MEMBER:
        case RGCP_DELETE_GROUP_MEMBER:
            // received passive packet -> handle in this thread
            retval = handle_passive_request(sock, packet);
            break;
        case RGCP_LEAVE_GROUP:
        case RGCP_JOIN_GROUP:
        case RGCP_CREATE_GROUP:
        case RGCP_GROUP_DISCOVER:
            // received impossible packet type
            retval = -1;
            break;
        default:
            // received unknown packet :(
            retval = -1;
            break;
    }

    pthread_mutex_unlock(&sock->socket_mtx);

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
                // TODO: set socket in error state
                // FIXME: how?
            }
        }        
    }

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

void rgcp_socket_close_all_connections(struct rgcp_socket *sock)
{
    struct list_head *current, *next;
    list_for_each_safe(current, next, &sock->group_connection_info.peer_list)
    {
        struct rgcp_peer *entry = list_entry(current, struct rgcp_peer, list);

        if (entry->peer_fd >= 0)
            close(entry->peer_fd);
    }

    while (!list_empty(&sock->group_connection_info.peer_list))
    {
        struct rgcp_peer *entry = list_first_entry(&sock->group_connection_info.peer_list, struct rgcp_peer, list);
        list_del(&entry->list);
        free(entry);
    }
}

int create_listen_socket(int *fd, struct sockaddr_in *addr, socklen_t *addrlen)
{
    *fd = socket(addr->sin_family, SOCK_STREAM, IPPROTO_TCP);

    if (*fd < 0)
        return -1;
    
    if (bind(*fd, (struct sockaddr *) addr, *addrlen) < 0)
    {
        perror("Bind of local listen socket failed");
        return -1;
    }

    if (listen(*fd, SOMAXCONN) < 0)
    {
        perror("Listening on local socket failed");
        return -1;
    }

    if (getsockname(*fd, (struct sockaddr *)addr, addrlen) < 0)
    {
        perror("Getting socket info failed");
        return -1;
    }

    return 0;
}

int rgcp_socket_init(int fd, struct rgcp_socket **sock, int domain)
{
    if (domain != AF_INET && domain != AF_INET6)
        return -1;

    pthread_t thread_id;

    (*sock) = calloc(sizeof(struct rgcp_socket), 1);
    (*sock)->sockfd = rgcp_get_next_socket_fd();
    (*sock)->middlewarefd = fd;
    (*sock)->connected_to_group = 0;
    (*sock)->received_response = 0;

    memset(&(*sock)->group_connection_info, 0, sizeof(struct rgcp_group_connection_info));
    list_init(&(*sock)->group_connection_info.peer_list);

    memset(&(*sock)->listen_socket_info, 0, sizeof(struct rgcp_listen_socket_info));

    struct sockaddr_in *listen_addr = &(*sock)->listen_socket_info.addr;

    listen_addr->sin_addr.s_addr = INADDR_ANY;
    listen_addr->sin_port = 0; // -> should assign random port
    listen_addr->sin_family = domain;

    (*sock)->listen_socket_info.addrlen = sizeof(*listen_addr);
    (*sock)->listen_socket_info.listenfd = -1;

    if (create_listen_socket(&(*sock)->listen_socket_info.listenfd, listen_addr, &(*sock)->listen_socket_info.addrlen) < 0)
        return -1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, (*sock)->thread_comms_channel) < 0)
        return -1;

    pthread_mutex_init(&(*sock)->socket_mtx, NULL);
    pthread_create(&thread_id, NULL, middleware_handler_thread, *sock);
    (*sock)->middleware_handler_thread_id = thread_id;

    list_add(&(*sock)->list, &rgcp_groupfd_list);

    return 0;
}

void rgcp_socket_free(struct rgcp_socket *sock)
{
    if (sock == NULL)
        return;

    pthread_kill(sock->middleware_handler_thread_id, SIGALRM);
    pthread_join(sock->middleware_handler_thread_id, NULL);

    close(sock->middlewarefd);
    sock->middlewarefd = -1;
    close(sock->thread_comms_channel[0]);
    close(sock->thread_comms_channel[1]);

    close(sock->listen_socket_info.listenfd);
    sock->listen_socket_info.listenfd = -1;

    rgcp_socket_close_all_connections(sock);
    free(sock->group_connection_info.groupname);

    list_del(&sock->list);
    free(sock);
}

void rgcp_group_info_init(struct rgcp_group_info *group_info)
{
    memset(group_info, 0, sizeof(*group_info));
}

void rgcp_group_info_free(struct rgcp_group_info *group_info)
{
    free(group_info->group_name);
    free(group_info->peers);
}

void rgcp_group_list_init(struct rgcp_group_list *group_list)
{
    memset(group_list, 0, sizeof(*group_list));
}

void rgcp_group_list_free(struct rgcp_group_list *group_list)
{
    for (uint32_t i = 0; i < group_list->group_count; i++)
    {
        rgcp_group_info_free(&group_list->groups[i]);
    }
    free(group_list->groups);
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

    struct rgcp_socket *sock = NULL;
    int fd = socket(domain, SOCK_STREAM, IPPROTO_TCP);

    if (fd < 0)
        goto error;

    // TODO: add host resolve here -> check if address is indeed valid + check if it resolves to valid ipv4/ipv6 host

    if (connect(fd, (struct sockaddr *) middleware_addr, sizeof(*middleware_addr)) < 0)
        goto error;

    if (rgcp_socket_init(fd, &sock, domain) < 0)
        goto error;

    // send our addr info to middleware
    union rgcp_packet_data data;
    memset(&data, 0, sizeof(data));

    data.peer.addr = sock->listen_socket_info.addr;
    data.peer.addrlen = sock->listen_socket_info.addrlen;

    if (rgcp_send_middleware_packet(sock, RGCP_ADDRINFO_SHARE, &data) < 0)
        goto error;

    return sock->sockfd;

error:
    rgcp_socket_free(sock);

    return -1;
}

int rgcp_get_group_info(int sockfd, struct rgcp_group_list *group_list)
{
    struct rgcp_socket *sock = rgcp_find_by_fd(sockfd);

    if (sock == NULL)
    {
        errno = ENOTSOCK;
        return -1;
    }

    if (rgcp_send_middleware_packet(sock, RGCP_GROUP_DISCOVER, NULL) <= 0)
        return -1;

    if (wait_with_interupt(&sock->received_response, RGCP_MIDDLEWARE_TIMEOUT) == 1)
    {
        pthread_mutex_lock(&sock->socket_mtx);

        // flip receive signal back to 0
        sock->received_response = 0;

        struct rgcp_packet *packet = NULL;
        union rgcp_packet_data data;
        memset(&data, 0, sizeof(data));

        if (read_from_thread_comms_channel(sock->thread_comms_channel[0], &packet) < 0)
            goto error;

        if (packet->type != RGCP_GROUP_DISCOVER_RESPONSE)
            goto error;

        if (rgcp_unpack(&data, packet) < 0)
            goto error;

        memset(group_list, 0, sizeof(*group_list));

        group_list->groups = calloc(data.groups.group_count, sizeof(struct rgcp_group_info));
        memcpy(group_list->groups, data.groups.groups, data.groups.group_count * sizeof(struct rgcp_group_info));
        group_list->group_count = data.groups.group_count;

        free(data.groups.groups);
        free(packet);
        pthread_mutex_unlock(&sock->socket_mtx);

        return 0;
    error:
        free(data.groups.groups);
        free(packet);
        pthread_mutex_unlock(&sock->socket_mtx);
        return -1;
    }
    else
    {
        // timeout reached return error
        fprintf(stderr, "[LIB] timeout in group disover\n");
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

    union rgcp_packet_data send_data;
    memset(&send_data, 0, sizeof(send_data));
    
    send_data.group_info.name_length = strlen(groupname) + 1; // +1 accounts for NULL byte
    send_data.group_info.group_name = calloc(send_data.group_info.name_length, sizeof(char));
    memcpy(send_data.group_info.group_name, groupname, send_data.group_info.name_length);
    
    send_data.group_info.peer_count = 0;
    send_data.group_info.peers = calloc(send_data.group_info.peer_count, sizeof(struct rgcp_peer_info));

    if (rgcp_send_middleware_packet(sock, RGCP_CREATE_GROUP, &send_data) <= 0)
        return -1;

    rgcp_group_info_free(&send_data.group_info);

    if (wait_with_interupt(&sock->received_response, RGCP_MIDDLEWARE_TIMEOUT) == 1)
    {
        pthread_mutex_lock(&sock->socket_mtx);

        // flip receive signal back to 0
        sock->received_response = 0;

        struct rgcp_packet *packet = NULL;

        if (read_from_thread_comms_channel(sock->thread_comms_channel[0], &packet) < 0)
        {
            printf("[LIB] group error: failed to read from communication channel\n");
            goto error;
        }

        if (
            packet->type != RGCP_CREATE_GROUP_OK && 
            packet->type != RGCP_CREATE_GROUP_ERROR_NAME &&
            packet->type != RGCP_CREATE_GROUP_ERROR_MAX_GROUPS && 
            packet->type != RGCP_CREATE_GROUP_ERROR_ALREADY_EXISTS
        )
        {
            printf("[LIB] group error: wrong packet type for function call: 0x%x\n", packet->type);
            goto error;
        }

        if (packet->type == RGCP_CREATE_GROUP_ERROR_NAME)
        {
            printf("[LIB] group error: name too long or zero\n");
            // FIXME: how to set errno here?
            goto error;
        }

        if (packet->type == RGCP_CREATE_GROUP_ERROR_MAX_GROUPS)
        {
            printf("[LIB] group error: max groups reached\n");
            // FIXME: how to set errno here?
            goto error;
        }

        if (packet->type == RGCP_CREATE_GROUP_ERROR_ALREADY_EXISTS)
        {    
            free(packet);
            pthread_mutex_unlock(&sock->socket_mtx);
            return 1;
        }

        free(packet);
        pthread_mutex_unlock(&sock->socket_mtx);

        return 0;
    error:
        free(packet);
        pthread_mutex_unlock(&sock->socket_mtx);
        return -1;
    }
    else
    {
        // timeout reached return error
        fprintf(stderr, "[LIB] timeout in create group\n");
        errno = ETIMEDOUT;
        return -1;
    }

    return 0;
}

int rgcp_connect(int sockfd, struct rgcp_group_info rgcp_group)
{
    struct rgcp_socket *sock = rgcp_find_by_fd(sockfd);

    if (sock == NULL)
    {
        errno = ENOTSOCK;
        return -1;
    }

    if (sock->connected_to_group == 1)
    {
        int res = rgcp_disconnect(sockfd);
        if (res < 0)
            return res;
    }

    union rgcp_packet_data send_data;
    memset(&send_data, 0, sizeof(send_data));
    
    send_data.group_info.name_length = rgcp_group.name_length;
    send_data.group_info.group_name = calloc(rgcp_group.name_length, sizeof(char));
    memcpy(send_data.group_info.group_name, rgcp_group.group_name, rgcp_group.name_length);

    // peers do not matter, because we get new info anyways
    send_data.group_info.peer_count = 0;
    send_data.group_info.peers = calloc(send_data.group_info.peer_count, sizeof(struct rgcp_peer_info));

    if (rgcp_send_middleware_packet(sock, RGCP_JOIN_GROUP, &send_data) <= 0)
        return -1;

    rgcp_group_info_free(&send_data.group_info);

    if (wait_with_interupt(&sock->received_response, RGCP_MIDDLEWARE_TIMEOUT) == 1)
    {
        pthread_mutex_lock(&sock->socket_mtx);

        // flip receive signal back to 0
        sock->received_response = 0;

        struct rgcp_packet *packet = NULL;
        union rgcp_packet_data recv_data;
        memset(&recv_data, 0, sizeof(recv_data));

        if (read_from_thread_comms_channel(sock->thread_comms_channel[0], &packet) < 0)
            goto error;

        if (
            packet->type != RGCP_JOIN_RESPONSE &&
            packet->type != RGCP_JOIN_ERROR_NO_SUCH_GROUP &&
            packet->type != RGCP_JOIN_ERROR_NAME &&
            packet->type != RGCP_JOIN_ERROR_MAX_CLIENTS && 
            packet->type != RGCP_JOIN_ERROR_ALREADY_IN_GROUP
        )
        {
            goto error;
        }

        if (packet->type == RGCP_JOIN_ERROR_NAME)
        {
            // FIXME: how to set errno here?
            printf("[LIB] name error\n");
            goto error;
        }

        if (packet->type == RGCP_JOIN_ERROR_NO_SUCH_GROUP)
        {
            // FIXME: how to set errno here?
            printf("[LIB] no group\n");
            goto error;
        }

        if (packet->type == RGCP_JOIN_ERROR_MAX_CLIENTS)
        {
            // FIXME: how to set errno here?
            printf("[LIB] max clients\n");
            goto error;
        }

        if (packet->type == RGCP_JOIN_ERROR_ALREADY_IN_GROUP)
        {
            // FIXME: how to set errno here?
            printf("[LIB] already in group\n");
            goto error;
        }

        // packet must be of type response
        if (rgcp_unpack(&recv_data, packet) < 0)
        {
            printf("[LIB] unpack failed\n");
            goto error;
        }
        
        sock->connected_to_group = 1;

        // TODO: connect() to all other peers
        for (uint32_t i = 0; i < recv_data.group_info.peer_count; i++)
        {
            struct rgcp_peer_info *remote_peer = &recv_data.group_info.peers[i];
            struct rgcp_peer *peer = calloc(sizeof(struct rgcp_peer), 1);

            peer->peer_fd = socket(remote_peer->addr.sin_family, SOCK_STREAM, IPPROTO_TCP);

            if (peer->peer_fd < 0)
                goto error;

            struct sockaddr_in addr = remote_peer->addr;
            
            if (connect(peer->peer_fd, (struct sockaddr *) & addr, sizeof(addr)) < 0)
                goto error;
            
            peer->addr = addr;
            peer->addrlen = sizeof(addr);

            list_add_tail(&peer->list, &sock->group_connection_info.peer_list);
        }

        // save groupname for when client wants to disconnect
        sock->group_connection_info.groupname = calloc(recv_data.group_info.name_length, sizeof(char));
        memcpy(sock->group_connection_info.groupname, recv_data.group_info.group_name, recv_data.group_info.name_length);

        free(packet);
        rgcp_group_info_free(&recv_data.group_info);
        pthread_mutex_unlock(&sock->socket_mtx);

        return 0;
    error:
        free(packet);
        rgcp_group_info_free(&recv_data.group_info);
        pthread_mutex_unlock(&sock->socket_mtx);
        return -1;
    }
    else
    {
        fprintf(stderr, "[LIB] timeout in connect\n");
        errno = ETIMEDOUT;
        return -1;
    }

    return 0;
}

int rgcp_disconnect(int sockfd)
{
    struct rgcp_socket *sock = rgcp_find_by_fd(sockfd);

    if (sock == NULL)
    {
        errno = ENOTSOCK;
        return -1;
    }

    if (sock->connected_to_group == 0)
        return 0;

    union rgcp_packet_data data;
    memset(&data, 0, sizeof(data));

    data.group_info.name_length = strlen(sock->group_connection_info.groupname) + 1;
    data.group_info.peer_count = 0;

    data.group_info.group_name = calloc(data.group_info.name_length, sizeof(char));
    data.group_info.peers = calloc(data.group_info.peer_count, sizeof(struct rgcp_peer_info));

    memcpy(data.group_info.group_name, sock->group_connection_info.groupname, data.group_info.name_length);

    if (rgcp_send_middleware_packet(sock, RGCP_LEAVE_GROUP, &data) < 0)
        return -1;

    rgcp_group_info_free(&data.group_info);

    return 0;
}

int rgcp_close(int sockfd)
{
    struct rgcp_socket *sock = rgcp_find_by_fd(sockfd);

    if (sock == NULL)
    {
        errno = ENOTSOCK;
        return -1;
    }

    if (sock->middlewarefd == -1)
    {
        rgcp_socket_free(sock);
        return 0;
    }

    if (rgcp_disconnect(sockfd) < 0)
    {
        rgcp_socket_free(sock);
        return -1;
    }

    rgcp_socket_free(sock);
    return 0;
}



ssize_t rgcp_send(int sockfd, const void *buf, size_t len, int flags)
{
    struct rgcp_socket *sock = rgcp_find_by_fd(sockfd);

    if (sock == NULL)
    {
        errno = ENOTSOCK;
        return -1;
    }

    pthread_mutex_lock(&sock->socket_mtx);

    if (buf == NULL)
    {
        pthread_mutex_unlock(&sock->socket_mtx);
        return -1;
    }

    if (sock->connected_to_group == 0)
    {
        pthread_mutex_unlock(&sock->socket_mtx);
        return -1;
    }

    fd_set write_fds;    
    ssize_t bytes_sent = 0;
    int max_fd = -1;
    struct list_head *current, *next;

    FD_ZERO(&write_fds);
    list_for_each_safe(current, next, &sock->group_connection_info.peer_list)
    {
        struct rgcp_peer *entry = list_entry(current, struct rgcp_peer, list);

        FD_SET(entry->peer_fd, &write_fds);

        max_fd = max(max_fd, entry->peer_fd);
    }

    if (max_fd == -1)
        return 0;

    struct timeval timeout;

    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    
    if (select(max_fd + 1, NULL, &write_fds, NULL, &timeout) < 0)
    {
        perror("Select in rgcp send failed");
        pthread_mutex_unlock(&sock->socket_mtx);
        return -1;
    }

    list_for_each_safe(current, next, &sock->group_connection_info.peer_list)
    {
        struct rgcp_peer *entry = list_entry(current, struct rgcp_peer, list);

        if (FD_ISSET(entry->peer_fd, &write_fds))
        {
            ssize_t res = 0;
            res = send(entry->peer_fd, buf, len, flags);

            if (res < 0)
            {
                // FIXME: client has error
                pthread_mutex_unlock(&sock->socket_mtx);
                return -1;
            }

            if (res == 0)
            {
                // FIXME: remote is closed
                continue;
            }

            bytes_sent += res;
        }
    }

    pthread_mutex_unlock(&sock->socket_mtx);

    return bytes_sent;
}

void rgcp_recv_data_init(struct rgcp_recv_data *recv_data)
{
    if (recv_data == NULL)  
        return;

    recv_data->buffer_count = 0;
    recv_data->buffer_length = 0;
    recv_data->buffers = NULL;
}

void rgcp_recv_data_free(struct rgcp_recv_data *recv_data)
{
    if (recv_data == NULL)
        return;

    for (size_t i = 0; i < recv_data->buffer_count; i++)
    {
        free(recv_data->buffers[i]);
    }

    free(recv_data->buffers);
}

ssize_t rgcp_recv(int sockfd, struct rgcp_recv_data *recv_data, size_t n_bytes, int flags)
{
    struct rgcp_socket *sock = rgcp_find_by_fd(sockfd);

    if (sock == NULL)
    {
        errno = ENOTSOCK;
        return -1;
    }

    pthread_mutex_lock(&sock->socket_mtx);

    if (recv_data == NULL)
    {
        pthread_mutex_unlock(&sock->socket_mtx);
        return -1;
    }

    if (sock->connected_to_group == 0)
    {
        pthread_mutex_unlock(&sock->socket_mtx);
        return -1;
    }

    recv_data->buffer_length = n_bytes;

    int peer_count = 0;
    ssize_t bytes_read = 0;
    struct list_head *current = NULL, *next = NULL;
    int max_fd = -1;
    fd_set readfds;

    FD_ZERO(&readfds);

    list_for_each_safe(current, next, &sock->group_connection_info.peer_list)
    {
        struct rgcp_peer *entry = list_entry(current, struct rgcp_peer, list);

        FD_SET(entry->peer_fd, &readfds);

        max_fd = max(entry->peer_fd, max_fd);
        peer_count++;
    }

    // no clients connected
    if (peer_count == 0)
    {
        pthread_mutex_unlock(&sock->socket_mtx);
        return 0;
    }

    struct timeval timeout;

    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    if (select(max_fd + 1, &readfds, NULL, NULL, &timeout) < 0)
    {
        perror("Select in rgcp recv failed");
        pthread_mutex_unlock(&sock->socket_mtx);
        return -1;
    }

    // set list iter vars to NULL again
    current = NULL;
    next = NULL;

    list_for_each_safe(current, next, &sock->group_connection_info.peer_list)
    {
        struct rgcp_peer *entry = list_entry(current, struct rgcp_peer, list);

        if (FD_ISSET(entry->peer_fd, &readfds))
        {
            char *buffer = calloc(n_bytes, sizeof(char));

            ssize_t res = recv(entry->peer_fd, buffer, n_bytes, flags);

            if (res < 0)
            {
                // FIXME: client has error
                free(buffer);
                pthread_mutex_unlock(&sock->socket_mtx);
                return -1;
            }

            if (res == 0)
            {
                // FIXME: remote is closed
                free(buffer);
                continue;
            }

            recv_data->buffer_count++;

            if (recv_data->buffers == NULL)
                recv_data->buffers = calloc(sizeof(recv_data->buffer_count), sizeof(char *));
            else
                recv_data->buffers = realloc(recv_data->buffers, recv_data->buffer_count * sizeof(char *));

            if (recv_data->buffers == NULL)
            {
                pthread_mutex_unlock(&sock->socket_mtx);
                return -1;
            }

            recv_data->buffers[recv_data->buffer_count - 1] = buffer;

            bytes_read += res;    
        }
    }

    pthread_mutex_unlock(&sock->socket_mtx);

    return bytes_read;
}
