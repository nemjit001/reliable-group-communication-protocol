#ifndef RGCP_GROUP
#define RGCP_GROUP

#include <stdlib.h>
#include <stdint.h>

#include "rgcp_peer.h"

struct _rgcp_group_t
{
    struct
    {
        uint32_t m_groupNameHash;
        size_t m_groupNameLength;
        char* m_pGroupName;
    } m_groupNameInfo;

    struct
    {
        size_t m_peerInfoCount;
        struct _rgcp_peer_info* m_pPeerInfos;
    } m_peerList;
} __attribute__((packed));

typedef struct _rgcp_group_t rgcp_group_t;

void rgcp_group_init(rgcp_group_t *pGroup);

void rgcp_group_free(rgcp_group_t group);

ssize_t serialize_rgcp_group(rgcp_group_t* pGroup, uint8_t* pOutBuffer);

int deserialize_rgcp_group(rgcp_group_t* pGroup, uint8_t* pDataBuffer, size_t bufferSize);

#endif
