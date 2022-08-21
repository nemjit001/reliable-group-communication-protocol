#ifndef RGCP_LIB_API_H
#define RGCP_LIB_API_H

#include <stdint.h>
#include <unistd.h>

#include <pthread.h>

enum RGCP_PACKET_TYPE
{
    RGCP_TYPE_HEARTBEAT_NOTIFY,
    RGCP_TYPE_SOCKET_CONNECT,
    RGCP_TYPE_SOCKET_DISCONNECT,
    RGCP_TYPE_SOCKET_DISCONNECT_RESPONSE,
    RGCP_TYPE_GROUP_DISCOVER,
    RGCP_TYPE_GROUP_DISCOVER_RESPONSE,
    RGCP_TYPE_GROUP_CREATE,
    RGCP_TYPE_GROUP_CREATE_RESPONSE,
    RGCP_TYPE_GROUP_JOIN,
    RGCP_TYPE_GROUP_JOIN_RESPONSE,
    RGCP_TYPE_GROUP_LEAVE,
    RGCP_TYPE_GROUP_LEAVE_RESPONSE,
    RGCP_TYPE_PEER_SHARE,
    RGCP_TYPE_PEER_REMOVE
};

enum RGCP_PACKET_ERROR
{
    RGCP_ERROR_NO_ERROR             = 0,
    RGCP_ERROR_NO_SUCH_GROUP        = 1,
    RGCP_ERROR_ALREADY_IN_GROUP     = 2,
    RGCP_ERROR_SHARING_ERROR        = 4
};

struct rgcp_packet
{
    enum RGCP_PACKET_TYPE m_packetType;
    enum RGCP_PACKET_ERROR m_packetError;
    uint32_t m_packetHash;
    uint32_t m_dataLen;
    uint8_t m_data[];
} __attribute__((packed));

int rgcp_packet_init(struct rgcp_packet** ppPacket, size_t dataLen);

void rgcp_packet_free(struct rgcp_packet* pPacket);

ssize_t rgcp_api_recv(int fd, pthread_mutex_t* pMtx, struct rgcp_packet** ppPacket);

ssize_t rgcp_api_send(int fd, pthread_mutex_t* pMtx, struct rgcp_packet* pPacket);

#endif
