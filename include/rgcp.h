#ifndef RGCP_H
#define RGCP_H

#include <stdint.h>
#include <sys/socket.h>

#define RGCP_MIDDLEWARE_PORT 8000
#define RGCP_MAX_PACKET_LENGTH 4096

enum rgcp_middleware_request_type
{
    RGCP_CONNECT,
    RGCP_CONNECT_OK,
    RGCP_MAX_CLIENTS,
    RGCP_GROUP_DISCOVERY,
    RGCP_GROUP_DISCOVERY_RESPONSE,
    RGCP_GROUP_CONNECT,
    RGCP_GROUP_DISCONNECT,
    RGCP_GROUP_DISCONNECT_OK,
    RGCP_DISCONNECT,
    RGCP_DISCONNECT_OK,
    RGCP_KEEPALIVE
};

struct rgcp_client_info
{
    struct sockaddr_in *addrinfo;
};

struct rgcp_group_info
{
    uint32_t group_id;
    uint32_t client_count;
    struct rgcp_client_info *clients;
};

struct rgcp_packet
{
    uint32_t id;
    enum rgcp_middleware_request_type type;
    size_t data_length;
    uint8_t data[];
} __attribute__((packed));

/**
 * @brief Create an RGCP socket connected to rgcp middleware
 */
int rgcp_socket(int domain, const char *middleware_hostname);

/**
 * @brief Get RGCP group info from middleware
 */
int rgcp_get_group_info(struct rgcp_group_info **groups, size_t *len);

/**
 * @brief Join an RGCP group
 */
int rgcp_connect(int sockfd, struct rgcp_group_info rgcp_group);

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
