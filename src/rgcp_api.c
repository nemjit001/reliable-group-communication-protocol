#include "rgcp_api.h"

#include "details/crc32.h"

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

ssize_t rgcp_api_recv(int fd, struct rgcp_packet** ppPacket)
{
    assert(fd >= 0);
    
    uint32_t packetLength = 0;
    if (recv(fd, &packetLength, sizeof(uint32_t), 0) < 0)
        return -1;

    if (packetLength == 0)
        return 0;

    uint8_t* buffer = calloc(packetLength, sizeof(uint8_t));
    if (!buffer)
        return -1;

    if (recv(fd, buffer, packetLength, 0) < 0)
    {
        free(buffer);
        return -1;
    }

    if (rgcp_packet_init(ppPacket, packetLength) < 0)
    {
        free(buffer);
        return -1;
    }

    uint32_t packetHash = CRC32_STR_DYNAMIC((char*)buffer, packetLength);

    memcpy(*ppPacket, buffer, packetLength);
    free(buffer);
    
    if (packetHash != (*ppPacket)->m_packetHash)
        return -1;

    return packetLength;
}

ssize_t rgcp_api_send(int fd, struct rgcp_packet* pPacket)
{
    assert(fd >= 0);
    assert(pPacket);

    uint32_t packetSize = sizeof(struct rgcp_packet) + pPacket->m_dataLen;
    uint8_t* buffer = calloc(packetSize, sizeof(uint8_t));

    if (!buffer)
        return -1;

    memcpy(buffer, pPacket, packetSize);
    uint32_t packetHash = CRC32_STR_DYNAMIC((char*)buffer, packetSize);

    assert(packetHash == pPacket->m_packetHash);
    if (packetHash != pPacket->m_packetHash)
    {
        free(buffer);
        return -1;
    }

    if (send(fd, &packetSize, sizeof(uint32_t), 0) < 0)
    {
        free(buffer);
        return -1;
    }
    
    if (send(fd, buffer, packetSize, 0) < 0)
    {
        free(buffer);
        return -1;
    }

    free(buffer);
    return packetSize;
}
