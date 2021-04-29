#ifndef RGCP_H
#define RGCP_H

#include <sys/socket.h>

// Unused protocol number for testing/development purposes, see https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml for reference
#define IPPROTO_RGCP 254

#define RGCP_GROUP 0x0
#define RGCP_REMOTE_ADDRESS 0x1

/**
 * @brief declaration of socket struct containing all relevant rgcp data for a connection
 */
struct rgcp_sock
{
    //
};

/**
 * @brief RGCP Packet for in-group communication, lightweight packet suitable for stream protocols, has data transfer capabilities.
 */
struct rgcp_ingroup_packet
{
    // TODO: fill out
} __attribute__((packed));

/**
 * @brief RGCP packet for group to group communication.
 */
struct rgcp_packet
{
    // TODO: fill out
} __attribute((packed));

/**
 * @brief Transmission Control Block, contains connection information, and manages packet stream data.
 */
struct rgcp_transmission_control_block
{
    // TODO: fill out
};

/**
 * @brief Master Transmission Control Block, contains in-group TCB info and a TCB for external communication.
 */
struct rgcp_master_transmission_control_block
{
    // TODO: fill out
};

/**
 * @brief Join an RGCP group that other clients can connect to, or connect to a remote address as an RGCP group.
 */
int rgcp_v4_connect(struct rgcp_sock *sk, struct sockaddr* addr, socklen_t addrlen, int flags);

/**
 * @brief Leave an RGCP group. If a group's last client disconnects or times out, the group is deleted.
 */
int rgcp_v4_close(struct rgcp_sock *sk);

/**
 * @brief Send data over the RGCP group to the remote address
 */
ssize_t rgcp_v4_send(struct rgcp_sock *sk, const void *buf, size_t len, int flags);

/**
 * @brief Receive data from the remote address
 */
ssize_t rgcp_v4_recv(struct rgcp_sock *sk, void *buf, size_t len, int flags);

/**
 * @brief Bind an RGCP group to an address:port combination, assigning this combination to the group.
 */
int rgcp_v4_bind(struct rgcp_sock *sk, const struct sockaddr *addr, socklen_t addrlen);

/**
 * @brief listen for incoming connections as an RGCP group, marks rgcp group as passive
 */
int rgcp_v4_listen(struct rgcp_sock *sk, int backlog);

/**
 * @brief Accept an incoming connection request
 */
int rgcp_v4_accept(struct rgcp_sock *sk, struct sockaddr* addr, socklen_t* addrlen);

#endif // RGCP_H
