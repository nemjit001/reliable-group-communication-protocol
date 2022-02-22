#include "rgcp_group.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>

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

ssize_t serialize_rgcp_group(rgcp_group_t* pGroup, uint8_t** ppOutBuffer)
{
    assert(pGroup);
    assert(ppOutBuffer);

    size_t nameInfoSize = sizeof(pGroup->m_groupNameInfo.m_groupNameHash) + sizeof(pGroup->m_groupNameInfo.m_groupNameLength) + (pGroup->m_groupNameInfo.m_groupNameLength * sizeof(char));
    size_t peerListSize = sizeof(pGroup->m_peerList.m_peerInfoCount) + (sizeof(struct _rgcp_peer_info) * pGroup->m_peerList.m_peerInfoCount);

    (*ppOutBuffer) = NULL;
    (*ppOutBuffer) = calloc(nameInfoSize + peerListSize, sizeof(uint8_t));

    assert(*ppOutBuffer);
    if ((*ppOutBuffer) == NULL)
        return -1;

    size_t ptrOffset = 0;
    
    memcpy(
        (*ppOutBuffer) + ptrOffset, 
        &(pGroup->m_groupNameInfo.m_groupNameHash), 
        sizeof(pGroup->m_groupNameInfo.m_groupNameHash)
    );

    ptrOffset += sizeof(pGroup->m_groupNameInfo.m_groupNameHash);

    memcpy(
        (*ppOutBuffer) + ptrOffset, 
        &(pGroup->m_groupNameInfo.m_groupNameLength), 
        sizeof(pGroup->m_groupNameInfo.m_groupNameLength)
    );

    ptrOffset += sizeof(pGroup->m_groupNameInfo.m_groupNameLength);

    memcpy(
        (*ppOutBuffer) + ptrOffset, 
        pGroup->m_groupNameInfo.m_pGroupName, 
        pGroup->m_groupNameInfo.m_groupNameLength
    );

    ptrOffset += pGroup->m_groupNameInfo.m_groupNameLength;

    memcpy(
        (*ppOutBuffer) + ptrOffset,
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
            (*ppOutBuffer) + ptrOffset + peerOffset,
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

ssize_t serialize_group_name_info(rgcp_group_info_t groupInfo, uint8_t **ppOutBuffer)
{
    assert(ppOutBuffer);

    (*ppOutBuffer) = NULL;
    size_t ptrSize = sizeof(groupInfo.m_groupNameHash) + sizeof(groupInfo.m_groupNameLength) + groupInfo.m_groupNameLength + 1;
    (*ppOutBuffer) = calloc(ptrSize, sizeof(uint8_t));

    if(!(*ppOutBuffer))
        return -1;
    
    size_t ptrOffset = 0;
    memcpy((*ppOutBuffer) + ptrOffset, &(groupInfo.m_groupNameHash), sizeof(groupInfo.m_groupNameHash));
    
    ptrOffset += sizeof(groupInfo.m_groupNameHash);
    memcpy((*ppOutBuffer) + ptrOffset, &(groupInfo.m_groupNameLength), sizeof(groupInfo.m_groupNameLength));

    ptrOffset += sizeof(groupInfo.m_groupNameLength);
    memcpy((*ppOutBuffer) + ptrOffset, groupInfo.m_pGroupName, groupInfo.m_groupNameLength);

    return ptrSize;
}

int deserialize_rgcp_group_name_info(rgcp_group_info_t* pGroupInfo, uint8_t* pBuffer, size_t bufferSize)
{
    assert(pBuffer);
    assert(pGroupInfo);
    assert(bufferSize >= (sizeof(uint32_t) * 2));

    size_t ptrOffset = 0;
    memcpy(&pGroupInfo->m_groupNameHash, pBuffer + ptrOffset, sizeof(uint32_t));

    ptrOffset += sizeof(uint32_t);
    memcpy(&pGroupInfo->m_groupNameLength, pBuffer + ptrOffset, sizeof(uint32_t));

    assert(bufferSize == (sizeof(uint32_t) * 2) + pGroupInfo->m_groupNameLength + 1);
    ptrOffset += sizeof(uint32_t);

    pGroupInfo->m_pGroupName = NULL;
    pGroupInfo->m_pGroupName = calloc(pGroupInfo->m_groupNameLength + 1, sizeof(char));
    if (pGroupInfo->m_pGroupName == NULL)
        return -1;

    memcpy(pGroupInfo->m_pGroupName, pBuffer + ptrOffset, pGroupInfo->m_groupNameLength);
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
