#include "rgcp.h"

#include "rgcp_api.h"
#include "details/rgcp_socket.h"

#include <errno.h>
#include <unistd.h>
#include <string.h>

int _share_host_info(int remoteFd, struct sockaddr_in hostAddr, socklen_t addrLen)
{
    struct _rgcp_peer_info hostInfo;
    hostInfo.m_addressInfo = hostAddr;
    hostInfo.m_addressLength = addrLen;

    uint8_t* pDataBuffer = NULL;
    ssize_t packetLength = serialize_rgcp_peer_info(&hostInfo, pDataBuffer);

    if (packetLength < 0)
    {
        free(pDataBuffer);
        return -1;
    }

    struct rgcp_packet* pPacket;
    if (rgcp_packet_init(&pPacket, packetLength) < 0)
    {
        free(pDataBuffer);
        return -1;
    }

    pPacket->m_dataLen = packetLength;
    pPacket->m_packetType = RGCP_TYPE_PEER_SHARE;
    memcpy(pPacket->m_data, pDataBuffer, packetLength);

    if (rgcp_api_send(remoteFd, pPacket) < 0)
    {
        rgcp_packet_free(pPacket);
        free(pDataBuffer);
        return -1;
    }

    rgcp_packet_free(pPacket);
    free(pDataBuffer);

    return 0;
}

int rgcp_socket(int domain, struct sockaddr* middlewareAddr, socklen_t addrLen)
{
    assert(middlewareAddr);

    if (domain != AF_INET && domain != AF_INET6)
    {
        errno = EPROTOTYPE;
        return -1;
    }

    if (!middlewareAddr)
    {
        errno = EDESTADDRREQ;
        return -1;
    }

    int middlewareFd = socket(domain, SOCK_STREAM, IPPROTO_TCP);
    if (middlewareFd < 0)
        return -1;

    if (connect(middlewareFd, middlewareAddr, addrLen) < 0)
    {
        close(middlewareFd);
        return -1;
    }

    rgcp_socket_t* pSocket = calloc(sizeof(rgcp_socket_t), 1);
    if (rgcp_socket_init(pSocket, middlewareFd, domain) < 0)
        return -1;

    if (_share_host_info(pSocket->m_middlewareFd, pSocket->m_listenSocketInfo.m_hostAdress, pSocket->m_listenSocketInfo.m_hostAdressLength) < 0)
    {
        rgcp_socket_free(pSocket);
        return -1;
    }

    return pSocket->m_RGCPSocketFd;
}

int rgcp_close(int sockfd)
{
    rgcp_socket_t* pSocket = NULL;

    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    if (pSocket->m_middlewareFd < 0)
        goto end;
    

    if (rgcp_disconnect(sockfd) < 0)
        goto error;

end:
    rgcp_socket_free(pSocket);
    free(pSocket);
    return 0;

error:
    rgcp_socket_free(pSocket);
    free(pSocket);
    return -1;
}

// TODO: implement
ssize_t rgcp_discover_groups(int sockfd, __attribute__((unused)) rgcp_group_t** ppGroups)
{
    rgcp_socket_t* pSocket = NULL;

    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    return -1;
}

// TODO: implement
int rgcp_create_group(int sockfd, __attribute__((unused)) const char* groupname)
{
    rgcp_socket_t* pSocket = NULL;

    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    return -1;
}

// TODO: implement
int rgcp_connect(int sockfd, __attribute__((unused)) rgcp_group_t group)
{
    rgcp_socket_t* pSocket = NULL;

    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    return -1;
}

// TODO: implement
int rgcp_disconnect(int sockfd)
{
    rgcp_socket_t* pSocket = NULL;

    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    return -1;
}

// TODO: implement
ssize_t rgcp_send(int sockfd, __attribute__((unused)) const char* buf, __attribute__((unused)) size_t len, __attribute__((unused)) enum RGCP_SEND_FLAGS flags)
{
    rgcp_socket_t* pSocket = NULL;

    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    return -1;
}

// TODO: implement
ssize_t rgcp_recv(int sockfd, __attribute__((unused)) rgcp_recv_data_t** ppRecvDataList)
{
    rgcp_socket_t* pSocket = NULL;

    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    return -1;
}
