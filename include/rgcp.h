#ifndef RGCP_H
#define RGCP_H

#include <sys/socket.h>

// See https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml for reference
#define IPPROTO_RGCP 254

/**
 * @brief Join an RGCP group that other clients can connect to, or connect to a remote address as an RGCP group.
 */
int rgcp_connect(int sockfd, struct sockaddr* addr, socklen_t addrlen, int flags);

/**
 * @brief Leave an RGCP group. If a group's last client disconnects or times out, the group is deleted.
 */
int rgcp_close(int sockfd);

/**
 * @brief Send data over the RGCP group to the remote address
 */
ssize_t rgcp_send(int sockfd, const void *buf, size_t len, int flags);

/**
 * @brief Receive data from the remote address
 */
ssize_t rgcp_recv(int sockfd, void *buf, size_t len, int flags);

/**
 * @brief Bind an RGCP group to an address:port combination, assigning this combination to the group.
 */
int rgcp_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

/**
 * @brief listen for incoming connections as an RGCP group, marks rgcp group as passive
 */
int rgcp_listen(int sockfd, int backlog);

/**
 * @brief Accept an incoming connection request
 */
int rgcp_accept(int sockfd, struct sockaddr* addr, socklen_t * addrlen);

#endif // RGCP_H
