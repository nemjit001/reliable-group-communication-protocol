#ifndef RGCP_H
#define RGCP_H

#include <stdlib.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <sys/socket.h>

enum rgcp_request_type
{
    RGCP_GROUP_DISCOVER,
    RGCP_GROUP_DISCOVER_RESPONSE,
    RGCP_CREATE_GROUP,
    RGCP_CREATE_GROUP_OK,
    RGCP_CREATE_GROUP_ERROR_NAME,
    RGCP_CREATE_GROUP_ERROR_GROUPS,
    RGCP_JOIN_GROUP,
    RGCP_JOIN_RESPONSE,
    RGCP_LEAVE_GROUP,
    RGCP_LEAVE_GROUP_OK,
    RGCP_NEW_GROUP_MEMBER,
    RGCP_DELETE_GROUP_MEMBER
};

struct rgcp_peer_info
{
    struct sockaddr_in addr;
    socklen_t addrlen;
} __attribute__((packed));

struct rgcp_group_info
{
    uint32_t name_length;
    char *group_name;
    uint32_t peer_count;
    struct rgcp_peer_info *peers;
} __attribute__((packed));

struct rgcp_group_list
{
    uint32_t group_count;
    struct rgcp_group_info *groups;
} __attribute__((packed));

union rgcp_packet_data
{
    struct rgcp_peer_info peer;
    struct rgcp_group_info group_info;
    struct rgcp_group_list groups;
} __attribute__((packed));

struct rgcp_packet
{
    uint32_t packet_len;
    enum rgcp_request_type type;
    uint8_t data[];
} __attribute__((packed));

void rgcp_group_info_init(struct rgcp_group_info *group_info);

void rgcp_group_info_free(struct rgcp_group_info *group_info);

void rgcp_group_list_init(struct rgcp_group_list *group_list);

void rgcp_group_list_free(struct rgcp_group_list *group_list);

/**
 * @brief Create an RGCP socket connected to rgcp middleware
 */
int rgcp_socket(int domain, struct sockaddr_in *middleware_addr);

/**
 * @brief Get RGCP group info from middleware
 */
int rgcp_get_group_info(int sockfd, struct rgcp_group_list *group_list);

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
