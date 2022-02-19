#include "rgcp_group.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

void rgcp_group_init(rgcp_group_t *pGroup)
{
    assert(pGroup);
    memset(pGroup, 0, sizeof(rgcp_group_t));
}

void rgcp_group_free(rgcp_group_t group)
{
    free(group.m_groupNameInfo.m_pGroupName);
    free(group.m_peerList.m_pPeerInfos);
    memset(&group, 0, sizeof(rgcp_group_t));
}

ssize_t serialize_rgcp_group(rgcp_group_t* pGroup, uint8_t* pOutBuffer)
{
    assert(pGroup);

    size_t nameInfoSize = sizeof(pGroup->m_groupNameInfo.m_groupNameHash) + sizeof(pGroup->m_groupNameInfo.m_groupNameLength) + (pGroup->m_groupNameInfo.m_groupNameLength * sizeof(char));
    size_t peerListSize = sizeof(pGroup->m_peerList.m_peerInfoCount) + (sizeof(struct _rgcp_peer_info) * pGroup->m_peerList.m_peerInfoCount);

    pOutBuffer = NULL;
    pOutBuffer = calloc(nameInfoSize + peerListSize, sizeof(uint8_t));

    assert(pOutBuffer);
    if (pOutBuffer == NULL)
        return -1;

    size_t ptrOffset = 0;
    
    memcpy(
        pOutBuffer + ptrOffset, 
        &(pGroup->m_groupNameInfo.m_groupNameHash), 
        sizeof(pGroup->m_groupNameInfo.m_groupNameHash)
    );

    ptrOffset += sizeof(pGroup->m_groupNameInfo.m_groupNameHash);

    memcpy(
        pOutBuffer + ptrOffset, 
        &(pGroup->m_groupNameInfo.m_groupNameLength), 
        sizeof(pGroup->m_groupNameInfo.m_groupNameLength)
    );

    ptrOffset += sizeof(pGroup->m_groupNameInfo.m_groupNameLength);

    memcpy(
        pOutBuffer + ptrOffset, 
        pGroup->m_groupNameInfo.m_pGroupName, 
        pGroup->m_groupNameInfo.m_groupNameLength
    );

    ptrOffset += pGroup->m_groupNameInfo.m_groupNameLength;

    memcpy(
        pOutBuffer + ptrOffset,
        &(pGroup->m_peerList.m_peerInfoCount),
        sizeof(pGroup->m_peerList.m_peerInfoCount)
    );

    ptrOffset += sizeof(pGroup->m_peerList.m_peerInfoCount);

    for (size_t i = 0; i < pGroup->m_peerList.m_peerInfoCount; i++)
    {
        size_t peerOffset = sizeof(struct _rgcp_peer_info) * i;
        uint8_t* pPeerInfoBuffer = NULL;
        serialize_rgcp_peer_info(&(pGroup->m_peerList.m_pPeerInfos[i]), &pPeerInfoBuffer);

        memcpy(
            pOutBuffer + ptrOffset + peerOffset,
            pPeerInfoBuffer,
            sizeof(struct _rgcp_peer_info)
        );

        free(pPeerInfoBuffer);
    }

    return (nameInfoSize + peerListSize);
}

int deserialize_rgcp_group(rgcp_group_t* pGroup, uint8_t* pDataBuffer, size_t bufferSize)
{
    assert(pDataBuffer);
    assert(pGroup);

    size_t ptrOffset = 0;

    memcpy(
        &(pGroup->m_groupNameInfo.m_groupNameHash),
        pDataBuffer + ptrOffset,
        sizeof(pGroup->m_groupNameInfo.m_groupNameHash)
    );

    ptrOffset += sizeof(pGroup->m_groupNameInfo.m_groupNameHash);

    if (ptrOffset > bufferSize)
        return -1;

    memcpy(
        &(pGroup->m_groupNameInfo.m_groupNameLength),
        pDataBuffer + ptrOffset,
        sizeof(pGroup->m_groupNameInfo.m_groupNameLength)
    );

    ptrOffset += sizeof(pGroup->m_groupNameInfo.m_groupNameLength);

    if (ptrOffset > bufferSize)
        return -1;

    pGroup->m_groupNameInfo.m_pGroupName = NULL;
    pGroup->m_groupNameInfo.m_pGroupName = calloc(pGroup->m_groupNameInfo.m_groupNameLength, sizeof(char));

    if (pGroup->m_groupNameInfo.m_pGroupName == NULL)
        return -1;

    memcpy(
        pGroup->m_groupNameInfo.m_pGroupName,
        pDataBuffer + ptrOffset,
        pGroup->m_groupNameInfo.m_groupNameLength
    );

    ptrOffset += pGroup->m_groupNameInfo.m_groupNameLength;

    if (ptrOffset > bufferSize)
        return -1;

    memcpy(
        &(pGroup->m_peerList.m_peerInfoCount),
        pDataBuffer + ptrOffset,
        sizeof(pGroup->m_peerList.m_peerInfoCount)
    );

    ptrOffset += sizeof(pGroup->m_peerList.m_peerInfoCount);

    if (ptrOffset > bufferSize)
        return -1;

    pGroup->m_peerList.m_pPeerInfos = NULL;
    pGroup->m_peerList.m_pPeerInfos = calloc(pGroup->m_peerList.m_peerInfoCount, sizeof(struct _rgcp_peer_info));

    if (pGroup->m_peerList.m_pPeerInfos == NULL)
        return -1;

    for (size_t i = 0; i < pGroup->m_peerList.m_peerInfoCount; i++)
    {
        size_t peerOffset = sizeof(struct _rgcp_peer_info) * i;

        if (ptrOffset + peerOffset > bufferSize)
            return -1;

        uint8_t* peerInfoBuffer = pDataBuffer + ptrOffset + peerOffset;
        deserialize_rgcp_peer_info(&(pGroup->m_peerList.m_pPeerInfos[i]), peerInfoBuffer, sizeof(struct _rgcp_peer_info));
    }

    return 0;
}

rgcp_group_t rgcp_group_from_info(rgcp_group_info_t groupInfo)
{
    rgcp_group_t group;
    memset(&group, 0, sizeof(rgcp_group_t));
    group.m_groupNameInfo.m_groupNameHash = groupInfo.m_groupNameHash;
    group.m_groupNameInfo.m_groupNameLength = groupInfo.m_groupNameLength;
    group.m_groupNameInfo.m_pGroupName = calloc(group.m_groupNameInfo.m_groupNameLength + 1, sizeof(char));
    memcpy(group.m_groupNameInfo.m_pGroupName, groupInfo.m_pGroupName, group.m_groupNameInfo.m_groupNameLength + 1);

    return group;
}
