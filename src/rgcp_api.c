#include "rgcp_api.h"
#include "rgcp_crc32.h"
#include "details/logger.h" 

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/socket.h>


int rgcp_packet_init(struct rgcp_packet** ppPacket, size_t dataLen)
{
    assert(ppPacket);

    size_t ptrSize = sizeof(struct rgcp_packet) + (dataLen * sizeof(uint8_t));

    (*ppPacket) = NULL;
    (*ppPacket) = malloc(ptrSize);

    assert(*ppPacket);
    if ((*ppPacket) == NULL)
        return -1;

    memset((*ppPacket), 0, ptrSize);
    return 0;
}

void rgcp_packet_free(struct rgcp_packet* pPacket)
{
    assert(pPacket);
    free(pPacket);
}

ssize_t rgcp_api_recv(int fd, pthread_mutex_t* pMtx, struct rgcp_packet** ppPacket)
{
    assert(fd >= 0);
    assert(pMtx);

    pthread_mutex_lock(pMtx);
    
    uint32_t packetLength = 0;
    if (recv(fd, &packetLength, sizeof(uint32_t), 0) < 0)
        goto error;

    if (packetLength == 0)
        goto end;

    uint8_t* buffer = calloc(packetLength, sizeof(uint8_t));
    if (!buffer)
        goto error;

    if (recv(fd, buffer, packetLength, 0) < 0)
    {
        free(buffer);
        goto error;
    }

    if (rgcp_packet_init(ppPacket, packetLength) < 0)
    {
        free(buffer);
        goto error;
    }

    memcpy(*ppPacket, buffer, packetLength);
    free(buffer);

    uint32_t receivedHash = (*ppPacket)->m_packetHash;
    (*ppPacket)->m_packetHash = 0;
    uint32_t actualPacketHash = RGCP_CRC32_DYNAMIC((uint8_t*)(*ppPacket), packetLength);

#ifndef NDEBUG
    if (receivedHash != actualPacketHash)
        log_msg("\t[Error on Hash]: %lu|%lu @ %p\n", receivedHash, actualPacketHash, *ppPacket);
#endif

    assert(receivedHash == actualPacketHash);

    if (receivedHash != actualPacketHash)
    {
        rgcp_packet_free(*ppPacket);
        goto error;
    }

end:
    pthread_mutex_unlock(pMtx);
    return packetLength;

error:
    pthread_mutex_unlock(pMtx);
    return -1;
}

ssize_t rgcp_api_send(int fd, pthread_mutex_t* pMtx, struct rgcp_packet* pPacket)
{
    assert(fd >= 0);
    assert(pPacket);
    assert(pMtx);

    pthread_mutex_lock(pMtx);

    uint32_t packetSize = sizeof(struct rgcp_packet) + pPacket->m_dataLen;
    uint8_t* buffer = calloc(packetSize, sizeof(uint8_t));

    if (!buffer)
        goto error;

    if (pPacket->m_dataLen > 0)
        assert(pPacket->m_data);

    pPacket->m_packetHash = 0;
    uint32_t packetHash = RGCP_CRC32_DYNAMIC((uint8_t*)(pPacket), packetSize);
    pPacket->m_packetHash = packetHash;

    memcpy(buffer, pPacket, packetSize);

    if (send(fd, &packetSize, sizeof(uint32_t), 0) < 0)
    {
        free(buffer);
        goto error;
    }
    
    if (send(fd, buffer, packetSize, 0) < 0)
    {
        free(buffer);
        goto error;
    }

    free(buffer);

    pthread_mutex_unlock(pMtx);
    return packetSize;

error:
    pthread_mutex_unlock(pMtx);
    return -1;
}
