#ifndef RGCP_H
#define RGCP_H

#include <sys/socket.h>

/**
 * @brief Join an existing RGCP group that another host has created.
 */
int rgcp_group_connect(int sockfd, struct sockaddr* addr, socklen_t addrlen);

/**
 * @brief Connect to a remote address and creates a new RGCP group with this client as master
 */
int rgcp_remote_connect(int sockfd, struct sockaddr* addr, socklen_t addrlen);

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
