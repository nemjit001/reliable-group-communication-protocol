#ifndef RGCP_PEER
#define RGCP_PEER

#include "linked_list.h"

#include <arpa/inet.h>

struct _rgcp_peer_info
{
    struct sockaddr_in m_addressInfo;
    socklen_t m_addressLength;
} __attribute__((packed));

struct _rgcp_peer_connection
{
    struct list_entry m_listEntry;
    int m_remoteFd;

    struct _rgcp_peer_info m_peerInfo;
};

ssize_t serialize_rgcp_peer_info(struct _rgcp_peer_info* pPeerInfo, uint8_t* pOutBuffer);

int deserialize_rgcp_peer_info(struct _rgcp_peer_info* pPeerInfo, uint8_t* pDataBuffer, size_t bufferSize);

#endif
