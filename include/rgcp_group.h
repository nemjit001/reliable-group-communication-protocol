#ifndef RGCP_LIB_GROUP_H
#define RGCP_LIB_GROUP_H

#include <stdlib.h>
#include <stdint.h>

#include "rgcp.h"
#include "rgcp_peer.h"

struct _rgcp_group_t
{
    rgcp_group_info_t m_groupNameInfo;

    struct
    {
        uint32_t m_peerInfoCount;
        struct _rgcp_peer_info* m_pPeerInfos;
    } m_peerList;
} __attribute__((packed));

typedef struct _rgcp_group_t rgcp_group_t;

void rgcp_group_init(rgcp_group_t *pGroup);

void rgcp_group_free(rgcp_group_t group);

void rgcp_group_info_free(rgcp_group_info_t groupInfo);

ssize_t serialize_rgcp_group(rgcp_group_t* pGroup, uint8_t** ppOutBuffer);

int deserialize_rgcp_group(rgcp_group_t* pGroup, uint8_t* pDataBuffer, size_t bufferSize);

ssize_t serialize_rgcp_group_name_info(rgcp_group_info_t groupInfo, uint8_t **ppOutBuffer);

int deserialize_rgcp_group_name_info(rgcp_group_info_t* pGroupInfo, uint8_t* pBuffer, size_t bufferSize);

#endif
