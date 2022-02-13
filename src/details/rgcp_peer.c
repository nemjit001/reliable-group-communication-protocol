#include "rgcp_peer.h"

#include <stdlib.h>
#include <string.h>

ssize_t serialize_rgcp_peer_info(struct _rgcp_peer_info* pPeerInfo, uint8_t* pOutBuffer)
{
    assert(pPeerInfo);

    if (!pPeerInfo)
        return -1;

    size_t peerInfoSize = sizeof(*pPeerInfo);

    pOutBuffer = NULL;
    pOutBuffer = calloc(peerInfoSize, sizeof(uint8_t));
    if (!pOutBuffer)
        return -1;

    memcpy(pOutBuffer, pPeerInfo, peerInfoSize);
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
