#ifndef RGCP_LIB_PEER_H
#define RGCP_LIB_PEER_H

#include <arpa/inet.h>

struct _rgcp_peer_info
{
    struct sockaddr_in m_addressInfo;
    socklen_t m_addressLength;
} __attribute__((packed));

ssize_t serialize_rgcp_peer_info(struct _rgcp_peer_info* pPeerInfo, uint8_t** ppOutBuffer);

int deserialize_rgcp_peer_info(struct _rgcp_peer_info* pPeerInfo, uint8_t* pDataBuffer, size_t bufferSize);

#endif
