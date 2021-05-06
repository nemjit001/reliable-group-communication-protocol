#include "rgcp.h"

#include "systems_headers.h"
#include "linklist.h"

LIST_HEAD(rgcp_groupfd_list);

struct rgcp_socket
{
    struct list_head list;
    int sockfd;
    int middlewarefd;

    pthread_t middleware_handler_thread_id;
};

static void thread_registersignals(int *sfd)
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

void *middleware_handler_thread(void *arg)
{
    struct rgcp_socket *sock = (struct rgcp_socket *)arg;

    ssize_t s;
    struct signalfd_siginfo fdsi;
    int sfd = -1;
    thread_registersignals(&sfd);

    if (sfd < 0)
    {
        perror("Blocking signals failed");
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

void rgcp_socket_init(int fd, struct rgcp_socket **sock)
{
    pthread_t thread_id;

    (*sock) = calloc(sizeof(struct rgcp_socket), 1);
    (*sock)->sockfd = rgcp_get_next_socket_fd();
    (*sock)->middlewarefd = fd;

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
    errno = ENOTSUP;
    return -1;
}

int rgcp_create_group(int sockfd, const char *groupname)
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
