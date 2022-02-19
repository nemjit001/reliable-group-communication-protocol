#include "rgcp.h"

#include "rgcp_api.h"
#include "details/logger.h"
#include "details/rgcp_socket.h"
#include "rgcp_group.h"

#include <errno.h>
#include <unistd.h>
#include <string.h>

int _share_host_info(int remoteFd, struct sockaddr_in hostAddr, socklen_t addrLen)
{
    struct _rgcp_peer_info hostInfo;
    hostInfo.m_addressInfo = hostAddr;
    hostInfo.m_addressLength = addrLen;

    uint8_t* pDataBuffer = NULL;
    ssize_t packetLength = serialize_rgcp_peer_info(&hostInfo, &pDataBuffer);

    if (!pDataBuffer)
        return -1;

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
    pPacket->m_packetType = RGCP_TYPE_SOCKET_CONNECT;
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

int rgcp_socket(int domain, struct sockaddr* middlewareaddr, socklen_t addrlen)
{
    assert(middlewareaddr);

    if (domain != AF_INET && domain != AF_INET6)
    {
        errno = EPROTOTYPE;
        return -1;
    }

    if (!middlewareaddr)
    {
        errno = EDESTADDRREQ;
        return -1;
    }

    int middlewareFd = socket(domain, SOCK_STREAM, IPPROTO_TCP);
    if (middlewareFd < 0)
        return -1;

    if (connect(middlewareFd, middlewareaddr, addrlen) < 0)
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

    log_msg("[Lib] Closing, Group Disconnect\n");

    if (rgcp_disconnect(sockfd) < 0)
        goto error;

    log_msg("[Lib] Group Disconnect Done\n");
    
    struct rgcp_packet* pPacket;
    rgcp_packet_init(&pPacket, 0);

    pPacket->m_dataLen = 0;
    pPacket->m_packetType = RGCP_TYPE_SOCKET_DISCONNECT;

    if (rgcp_api_send(pSocket->m_middlewareFd, pPacket) < 0)
    {
        rgcp_packet_free(pPacket);
        goto error;
    }

    log_msg("[Lib] Socket Disconnect Done\n");

    rgcp_packet_free(pPacket);
end:
    rgcp_socket_free(pSocket);
    free(pSocket);
    return 0;

error:
    log_msg("[Lib] Disconnect Error\n");

    rgcp_socket_free(pSocket);
    free(pSocket);
    return -1;
}

ssize_t rgcp_discover_groups(int sockfd, __attribute__((unused)) rgcp_group_info_t** pp_groups)
{
    rgcp_socket_t* pSocket = NULL;

    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    struct rgcp_packet* pPacket;
    rgcp_packet_init(&pPacket, 0);

    pPacket->m_dataLen = 0;
    pPacket->m_packetType = RGCP_TYPE_GROUP_DISCOVER;

    log_msg("[Lib] Sending Discover Request\n");
    if (rgcp_api_send(pSocket->m_middlewareFd, pPacket) < 0)
    {
        rgcp_packet_free(pPacket);
        return -1;
    }

    rgcp_packet_free(pPacket);
    // Reusing packet ptr to store response data
    pPacket = NULL;

    if (rgcp_helper_recv(pSocket, &pPacket, RGCP_SOCKET_TIMEOUT_MS) < 0)
        return -1;

    log_msg("[Lib][%p] Received Discover Response\n", pSocket);
    
    // TODO: handle response

    return 0;
}

int rgcp_create_group(int sockfd, const char* groupname, size_t namelen)
{
    assert(groupname);
    rgcp_socket_t* pSocket = NULL;

    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    assert(strlen(groupname) == namelen);
    if (strlen(groupname) != namelen)
        return -1;

    struct rgcp_packet* pPacket;
    rgcp_packet_init(&pPacket, namelen + 1);

    pPacket->m_packetType = RGCP_TYPE_GROUP_CREATE;
    pPacket->m_dataLen = namelen + 1;
    memset(pPacket->m_data, 0, namelen + 1);
    memcpy(pPacket->m_data, groupname, namelen);

    if (rgcp_api_send(pSocket->m_middlewareFd, pPacket) < 0)
    {
        rgcp_packet_free(pPacket);
        return -1;
    }

    rgcp_packet_free(pPacket);
    // Reusing packet ptr to store response data
    pPacket = NULL;

    if (rgcp_helper_recv(pSocket, &pPacket, RGCP_SOCKET_TIMEOUT_MS) < 0)
        return -1;

    log_msg("[Lib][%p] Create Group Response\n", pSocket);
    
    // TODO: handle response

    return -1;
}

int rgcp_connect(int sockfd, rgcp_group_info_t group)
{
    rgcp_socket_t* pSocket = NULL;

    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    rgcp_group_t rgcpGroup = rgcp_group_from_info(group);
    uint8_t* pDataBuff = NULL;
    ssize_t bufferSize = serialize_rgcp_group(&rgcpGroup, pDataBuff);

    if (bufferSize < 0)
        return -1;

    struct rgcp_packet* pPacket;
    rgcp_packet_init(&pPacket, bufferSize);

    pPacket->m_packetType = RGCP_TYPE_GROUP_JOIN;
    pPacket->m_dataLen = bufferSize;
    memcpy(pPacket->m_data, pDataBuff, bufferSize);

    if (rgcp_api_send(pSocket->m_middlewareFd, pPacket) < 0)
    {
        rgcp_packet_free(pPacket);
        free(pDataBuff);
        return -1;
    }

    rgcp_packet_free(pPacket);
    free(pDataBuff);
    // Reusing packet ptr to store response data
    pPacket = NULL;

    if (rgcp_helper_recv(pSocket, &pPacket, RGCP_SOCKET_TIMEOUT_MS) < 0)
        return -1;

    log_msg("[Lib][%p] Received Group Join Response\n", pSocket);
    
    // TODO: handle response

    return -1;
}

int rgcp_disconnect(int sockfd)
{
    rgcp_socket_t* pSocket = NULL;
    
    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    struct rgcp_packet* pPacket;
    rgcp_packet_init(&pPacket, 0);

    pPacket->m_dataLen = 0;
    pPacket->m_packetType = RGCP_TYPE_GROUP_LEAVE;

    log_msg("[Lib] Group Disconnect Notice\n");

    if (rgcp_api_send(pSocket->m_middlewareFd, pPacket) < 0)
    {
        rgcp_packet_free(pPacket);
        return -1;
    }

    log_msg("[Lib] Group Disconnect Notice Sent\n");

    rgcp_packet_free(pPacket);

    return 0;
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
