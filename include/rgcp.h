#ifndef RGCP_H
#define RGCP_H

#include <sys/socket.h>

/**
 * @brief Create an RGCP socket
 */
int rgcp_socket(int domain);

/**
 * @brief Join an RGCP group
 */
int rgcp_connect(int sockfd, struct sockaddr *addr, socklen_t addrlen);

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

#endif // RGCP_H
