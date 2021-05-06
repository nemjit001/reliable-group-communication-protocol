#ifndef RGCP_H
#define RGCP_H

#include <stdint.h>
#include <netinet/ip.h>
#include <sys/socket.h>

struct rgcp_peer_info
{
    struct sockaddr_in addr;
    socklen_t addrlen;
};

struct rgcp_group_info
{
    char *group_name;
    int peer_count;
    struct rgcp_peer_info *peer;
};

/**
 * @brief Create an RGCP socket connected to rgcp middleware
 */
int rgcp_socket(int domain, struct sockaddr_in *middleware_addr);

/**
 * @brief Get RGCP group info from middleware
 */
int rgcp_get_group_info(int sockfd, struct rgcp_group_info **groups, size_t *len);

/**
 * @brief Ceate RGCP group
 */
int rgcp_create_group(int sockfd, const char *groupname);

/**
 * @brief Join an RGCP group
 */
int rgcp_connect(int sockfd, struct rgcp_group_info rgcp_group);

/**
 * @brief Free socket resources and leave an RGCP group if connected to one. If a group's last client disconnects or times out, the group is deleted.
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
