#include "rgcp_peer.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

ssize_t serialize_rgcp_peer_info(struct _rgcp_peer_info* pPeerInfo, uint8_t** ppOutBuffer)
{
    assert(pPeerInfo);

    if (!pPeerInfo)
        return -1;

    size_t peerInfoSize = sizeof(struct _rgcp_peer_info);

    *ppOutBuffer = NULL;
    *ppOutBuffer = calloc(peerInfoSize, sizeof(uint8_t));
    if (!(*ppOutBuffer))
        return -1;

    memcpy((*ppOutBuffer), pPeerInfo, peerInfoSize);
    return peerInfoSize;
}

int deserialize_rgcp_peer_info(struct _rgcp_peer_info* pPeerInfo, uint8_t* pDataBuffer, size_t bufferSize)
{
    assert(pDataBuffer);
    assert(pPeerInfo);
    assert(bufferSize == sizeof(struct _rgcp_peer_info));

    if (!pDataBuffer || !pPeerInfo || bufferSize != sizeof(struct _rgcp_peer_info))
        return -1;

    memcpy(pPeerInfo, pDataBuffer, bufferSize);
    return 0;
}
