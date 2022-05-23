#include "rgcp.h"

#include "rgcp_api.h"
#include "details/logger.h"
#include "details/rgcp_socket.h"
#include "rgcp_group.h"

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>

int _share_host_info(rgcp_socket_t* pSocket)
{
    struct _rgcp_peer_info hostInfo;
    hostInfo.m_addressInfo = pSocket->m_listenSocketInfo.m_hostAdress;
    hostInfo.m_addressLength = pSocket->m_listenSocketInfo.m_hostAdressLength;

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

    if (rgcp_api_send(pSocket->m_middlewareFd, &pSocket->m_apiMtxes.m_sendMtx, pPacket) < 0)
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
    if (rgcp_socket_init(pSocket, middlewareFd, domain, RGCP_SOCKET_HEARTBEAT_PERIOD_SECONDS) < 0)
        return -1;

    pthread_mutex_lock(&pSocket->m_socketMtx);

    if (_share_host_info(pSocket) < 0)
    {
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        rgcp_socket_free(pSocket);
        return -1;
    }

    pthread_mutex_unlock(&pSocket->m_socketMtx);
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

    pthread_mutex_lock(&pSocket->m_socketMtx);

    if (pSocket->m_middlewareFd < 0)
        goto end;

    log_msg("[Lib][%d] Closing, Group Disconnect\n", pSocket->m_RGCPSocketFd);

    if (pSocket->m_peerData.m_bConnectedToGroup)
    {
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        if (rgcp_disconnect(sockfd) < 0)
        {
            pthread_mutex_lock(&pSocket->m_socketMtx);
            goto error;
        }

        pthread_mutex_lock(&pSocket->m_socketMtx);
    }
    
    struct rgcp_packet* pPacket;
    rgcp_packet_init(&pPacket, 0);

    pPacket->m_dataLen = 0;
    pPacket->m_packetType = RGCP_TYPE_SOCKET_DISCONNECT;

    if (rgcp_api_send(pSocket->m_middlewareFd, &pSocket->m_apiMtxes.m_sendMtx, pPacket) < 0)
    {
        rgcp_packet_free(pPacket);
        goto error;
    }

    log_msg("[Lib][%d] Sent Socket Disconnect Notice\n", pSocket->m_RGCPSocketFd);

    rgcp_packet_free(pPacket);
    // Reusing packet ptr to store response data
    pPacket = NULL;

    if (rgcp_helper_recv(pSocket, &pPacket, RGCP_SOCKET_TIMEOUT_MS) < 0)
        goto error;

    log_msg("[Lib][%d] Received Disconnect Response\n", pSocket->m_RGCPSocketFd);

    if (pPacket->m_packetType != RGCP_TYPE_SOCKET_DISCONNECT_RESPONSE || pPacket->m_packetError != RGCP_ERROR_NO_ERROR)
    { 
        rgcp_packet_free(pPacket);
        goto error;
    }

    rgcp_packet_free(pPacket);
    log_msg("[Lib][%d] Socket Disconnect Done\n", pSocket->m_RGCPSocketFd);
    
end:
    pthread_mutex_unlock(&pSocket->m_socketMtx);
    rgcp_socket_free(pSocket);
    free(pSocket);
    return 0;

error:
    log_msg("[Lib][%d] Disconnect Error, cleaning up anyway\n", pSocket->m_RGCPSocketFd);

    pthread_mutex_unlock(&pSocket->m_socketMtx);
    rgcp_socket_free(pSocket);
    free(pSocket);
    return -1;
}

ssize_t rgcp_discover_groups(int sockfd, rgcp_group_info_t*** ppp_group_infos)
{
    if (ppp_group_infos == NULL)
        return -1;
    
    (*ppp_group_infos) = NULL;
    rgcp_socket_t* pSocket = NULL;

    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    pthread_mutex_lock(&pSocket->m_socketMtx);

    struct rgcp_packet* pPacket;
    rgcp_packet_init(&pPacket, 0);

    pPacket->m_dataLen = 0;
    pPacket->m_packetType = RGCP_TYPE_GROUP_DISCOVER;

    log_msg("[Lib][%d] Sending Discover Request\n", pSocket->m_RGCPSocketFd);
    if (rgcp_api_send(pSocket->m_middlewareFd, &pSocket->m_apiMtxes.m_sendMtx, pPacket) < 0)
    {
        rgcp_packet_free(pPacket);
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    rgcp_packet_free(pPacket);
    // Reusing packet ptr to store response data
    pPacket = NULL;

    if (rgcp_helper_recv(pSocket, &pPacket, RGCP_SOCKET_TIMEOUT_MS) < 0)
    {
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    log_msg("[Lib][%d] Received Discover Response\n", pSocket->m_RGCPSocketFd);
    
    if (pPacket->m_packetType != RGCP_TYPE_GROUP_DISCOVER_RESPONSE || pPacket->m_packetError != RGCP_ERROR_NO_ERROR)
    { 
        rgcp_packet_free(pPacket);
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    if (pPacket->m_dataLen == 0)
    {
        rgcp_packet_free(pPacket);
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return 0;
    }

    // deserialize group name info
    size_t ptrOffset = 0;
    size_t groupInfoCount = 0;
    while(ptrOffset < pPacket->m_dataLen)
    {
        uint32_t ptrSize = 0;
        memcpy(&ptrSize, pPacket->m_data + ptrOffset, sizeof(uint32_t));
        ptrOffset += sizeof(uint32_t);

        assert(ptrSize > 0);
        rgcp_group_info_t* pGroupInfo = calloc(sizeof(rgcp_group_info_t), 1);
        if (deserialize_rgcp_group_name_info(pGroupInfo, pPacket->m_data + ptrOffset, ptrSize) < 0)
        {
            log_msg("[Lib][%d] Group Info deserialization failed\n", pSocket->m_RGCPSocketFd);
            rgcp_packet_free(pPacket);
            pthread_mutex_unlock(&pSocket->m_socketMtx);
            return -1;
        }

        ptrOffset += (pGroupInfo->m_groupNameLength + 1 + sizeof(pGroupInfo->m_groupNameHash) + sizeof(pGroupInfo->m_groupNameLength));
        
        log_msg("[Lib][%d][GroupInfo #%d] 0x%x %u %s\n", pSocket->m_RGCPSocketFd, groupInfoCount, pGroupInfo->m_groupNameHash, pGroupInfo->m_groupNameLength, pGroupInfo->m_pGroupName);
        groupInfoCount++;

        (*ppp_group_infos) = realloc((*ppp_group_infos), groupInfoCount * sizeof(rgcp_group_info_t*));
        (*ppp_group_infos)[groupInfoCount - 1] = pGroupInfo;
    }

    rgcp_packet_free(pPacket);
    pthread_mutex_unlock(&pSocket->m_socketMtx);
    return groupInfoCount;
}

int rgcp_free_group_infos(rgcp_group_info_t*** ppp_group_infos, ssize_t group_count)
{
    assert(ppp_group_infos);

    if (group_count < 0 || ppp_group_infos == NULL)
        return -1;

    if (*ppp_group_infos == NULL)
        return 0;

    log_msg("[Lib] Freeing group info array (%d info(s))\n", group_count);
    for (ssize_t i = 0; i < group_count; i++)
    {
        log_msg("\t[ #%d @ %p ]\n", i, &(*ppp_group_infos));
        free((*ppp_group_infos)[i]->m_pGroupName);
        free((*ppp_group_infos)[i]);
    }

    free(*ppp_group_infos);
    (*ppp_group_infos) = NULL;

    return 0;
}

int rgcp_create_group(int sockfd, const char* groupname, size_t namelen)
{
    assert(groupname);
    if (groupname == NULL)
        return -1;

    rgcp_socket_t* pSocket = NULL;

    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    pthread_mutex_lock(&pSocket->m_socketMtx);

    assert(strlen(groupname) == namelen);
    if (strlen(groupname) != namelen)
    {
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    struct rgcp_packet* pPacket;
    rgcp_packet_init(&pPacket, namelen + 1);

    pPacket->m_packetType = RGCP_TYPE_GROUP_CREATE;
    pPacket->m_dataLen = namelen + 1;
    memcpy(pPacket->m_data, groupname, namelen);
    pPacket->m_data[namelen] = '\0';

    if (rgcp_api_send(pSocket->m_middlewareFd, &pSocket->m_apiMtxes.m_sendMtx, pPacket) < 0)
    {
        rgcp_packet_free(pPacket);
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    rgcp_packet_free(pPacket);
    // Reusing packet ptr to store response data
    pPacket = NULL;

    if (rgcp_helper_recv(pSocket, &pPacket, RGCP_SOCKET_TIMEOUT_MS) < 0)
    {
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    log_msg("[Lib][%d] Create Group Response\n", pSocket->m_RGCPSocketFd);
    
    if (pPacket->m_packetType != RGCP_TYPE_GROUP_CREATE_RESPONSE || pPacket->m_packetError != RGCP_ERROR_NO_ERROR)
    { 
        rgcp_packet_free(pPacket);
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    rgcp_packet_free(pPacket);
    pthread_mutex_unlock(&pSocket->m_socketMtx);
    return 0;
}

int rgcp_connect(int sockfd, rgcp_group_info_t group_info)
{
    rgcp_socket_t* pSocket = NULL;

    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    pthread_mutex_lock(&pSocket->m_socketMtx);

    if (pSocket->m_peerData.m_bConnectedToGroup == 1)
    {
        errno = EISCONN;
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    uint8_t* pDataBuff = NULL;
    ssize_t bufferSize = serialize_rgcp_group_name_info(group_info, &pDataBuff);

    if (bufferSize < 0)
    {
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    struct rgcp_packet* pPacket;
    rgcp_packet_init(&pPacket, bufferSize);

    pPacket->m_packetType = RGCP_TYPE_GROUP_JOIN;
    pPacket->m_dataLen = bufferSize;
    memcpy(pPacket->m_data, pDataBuff, bufferSize);

    if (rgcp_api_send(pSocket->m_middlewareFd, &pSocket->m_apiMtxes.m_sendMtx, pPacket) < 0)
    {
        rgcp_packet_free(pPacket);
        free(pDataBuff);
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    rgcp_packet_free(pPacket);
    free(pDataBuff);
    // Reusing packet ptr to store response data
    pPacket = NULL;

    if (rgcp_helper_recv(pSocket, &pPacket, RGCP_SOCKET_TIMEOUT_MS) < 0)
    {
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    log_msg("[Lib][%d] Received Group Join Response\n", pSocket->m_RGCPSocketFd);

    assert(pPacket->m_packetType == RGCP_TYPE_GROUP_JOIN_RESPONSE);

    if (pPacket->m_packetError != RGCP_ERROR_NO_ERROR)
    {
        log_msg("[Lib][%d] Received error on join: %d\n", pSocket->m_RGCPSocketFd, pPacket->m_packetError);
        rgcp_packet_free(pPacket);
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }
    
    rgcp_group_t group;
    if (deserialize_rgcp_group(&group, pPacket->m_data, pPacket->m_dataLen) < 0)
    {
        rgcp_packet_free(pPacket);
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    for (uint32_t i = 0; i < group.m_peerList.m_peerInfoCount; i++)
    {
        if (rgcp_socket_connect_to_peer(pSocket, group.m_peerList.m_pPeerInfos[i]) < 0)
        {
            errno = ECONNABORTED;

            rgcp_group_free(group);
            rgcp_packet_free(pPacket);
            pthread_mutex_unlock(&pSocket->m_socketMtx);
            return -1;
        }
    }

    pSocket->m_peerData.m_bConnectedToGroup = 1;
    rgcp_group_free(group);
    rgcp_packet_free(pPacket);
    pthread_mutex_unlock(&pSocket->m_socketMtx);
    return 0;
}

int rgcp_is_connected(int sockfd)
{
    rgcp_socket_t* pSocket = NULL;

    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    pthread_mutex_lock(&pSocket->m_socketMtx);

    int bConnected = pSocket->m_peerData.m_bConnectedToGroup;

    pthread_mutex_unlock(&pSocket->m_socketMtx);
    return bConnected;
}

ssize_t rgcp_peer_count(int sockfd)
{
    rgcp_socket_t* pSocket = NULL;
    
    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    pthread_mutex_lock(&pSocket->m_socketMtx);
    pthread_mutex_lock(&pSocket->m_peerData.m_peerMtx);

    ssize_t count = 0;

    struct list_entry *pCurr, *pNext;
    LIST_FOR_EACH(pCurr, pNext, &pSocket->m_peerData.m_connectedPeers)
    {
        struct _rgcp_peer_connection *pConn = LIST_ENTRY(pCurr, struct _rgcp_peer_connection, m_listEntry);
        assert(pConn);

        char* peerIpAddr = inet_ntoa(pConn->m_peerInfo.m_addressInfo.sin_addr);
        log_msg("[Lib][%d] Peer @ %p (%s:%u) [connected: %d]\n", pSocket->m_RGCPSocketFd, (void*)pConn, peerIpAddr, pConn->m_peerInfo.m_addressInfo.sin_port, pConn->m_bEstablished);

        if (pConn->m_bEstablished)
            count++;
    }

    pthread_mutex_unlock(&pSocket->m_socketMtx);
    pthread_mutex_unlock(&pSocket->m_peerData.m_peerMtx);

    return count;
}

int rgcp_disconnect(int sockfd)
{
    rgcp_socket_t* pSocket = NULL;
    
    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    pthread_mutex_lock(&pSocket->m_socketMtx);

    struct rgcp_packet* pPacket;
    rgcp_packet_init(&pPacket, 0);

    pPacket->m_dataLen = 0;
    pPacket->m_packetType = RGCP_TYPE_GROUP_LEAVE;

    if (rgcp_api_send(pSocket->m_middlewareFd, &pSocket->m_apiMtxes.m_sendMtx, pPacket) < 0)
    {
        rgcp_packet_free(pPacket);
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    log_msg("[Lib][%d] Group Disconnect Notice Sent\n", pSocket->m_RGCPSocketFd);
    rgcp_packet_free(pPacket);
    pPacket = NULL;

    if (rgcp_helper_recv(pSocket, &pPacket, RGCP_SOCKET_TIMEOUT_MS) < 0)
    {
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    if (pPacket->m_packetType != RGCP_TYPE_GROUP_LEAVE_RESPONSE || pPacket->m_packetError != RGCP_ERROR_NO_ERROR)
    {
        rgcp_packet_free(pPacket);
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    pthread_mutex_lock(&pSocket->m_peerData.m_peerMtx);

    struct list_entry *pCurr, *pNext;
    LIST_FOR_EACH(pCurr, pNext, &pSocket->m_peerData.m_connectedPeers)
    {
        struct _rgcp_peer_connection* pConnection = LIST_ENTRY(pCurr, struct _rgcp_peer_connection, m_listEntry);

        list_del(pCurr);
        close(pConnection->m_remoteFd);
        free(pConnection);
    }

    pthread_mutex_unlock(&pSocket->m_peerData.m_peerMtx);

    pSocket->m_peerData.m_bConnectedToGroup = 0;
    rgcp_packet_free(pPacket);
    pthread_mutex_unlock(&pSocket->m_socketMtx);
    return 0;
}

ssize_t rgcp_send(int sockfd, const char* buf, size_t len, enum RGCP_SEND_FLAGS flags)
{
    rgcp_socket_t* pSocket = NULL;

    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    pthread_mutex_lock(&pSocket->m_socketMtx);
    pthread_mutex_lock(&pSocket->m_peerData.m_peerMtx);

    if (!pSocket->m_peerData.m_bConnectedToGroup)
    {
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        pthread_mutex_unlock(&pSocket->m_peerData.m_peerMtx);
        return 0;
    }

    ssize_t totalBytesSent = 0;

    if (flags & RGCP_SEND_BROADCAST || flags == 0)
    {
        struct list_entry *pCurr, *pNext;
        LIST_FOR_EACH(pCurr, pNext, &pSocket->m_peerData.m_connectedPeers)
        {
            struct _rgcp_peer_connection *pConn = LIST_ENTRY(pCurr, struct _rgcp_peer_connection, m_listEntry);
            assert(pConn);
            
            if (!pConn->m_bEstablished)
                continue;

            uint32_t buffSize = (uint32_t)len;
            ssize_t bytesSent = send(pConn->m_remoteFd, &buffSize, sizeof(buffSize), 0);
            
            if (bytesSent < 0)
            {
                log_msg("[Lib][%d] Failed to send buffer size to peer %d\n", pSocket->m_RGCPSocketFd, pConn->m_remoteFd);
                continue;
            }

            bytesSent += send(pConn->m_remoteFd, buf, len, 0);
            if (bytesSent < 0)
            {
                log_msg("[Lib][%d] Failed to send data buffer to peer %d\n", pSocket->m_RGCPSocketFd, pConn->m_remoteFd);
                continue;
            }

            log_msg("[Lib][%d] Sent buffer (%lu bytes) to peer %d\n", pSocket->m_RGCPSocketFd, buffSize, pConn->m_remoteFd);

            totalBytesSent += bytesSent;
        }
    }
    else
    {
        errno = ENOTSUP;
        pthread_mutex_unlock(&pSocket->m_peerData.m_peerMtx);
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    pthread_mutex_unlock(&pSocket->m_peerData.m_peerMtx);
    pthread_mutex_unlock(&pSocket->m_socketMtx);
    return totalBytesSent;
}

ssize_t rgcp_recv(int sockfd, rgcp_recv_data_t** ppRecvDataList)
{
    rgcp_socket_t* pSocket = NULL;

    if (rgcp_socket_get(sockfd, &pSocket) < 0)
    {
        errno = ENOTSOCK;
        return -1;
    }

    pthread_mutex_lock(&pSocket->m_socketMtx);
    pthread_mutex_lock(&pSocket->m_peerData.m_peerMtx);

    ssize_t fdCount = 0;
    struct pollfd* pollFds = NULL;

    struct list_entry *pCurr, *pNext;
    LIST_FOR_EACH(pCurr, pNext, &pSocket->m_peerData.m_connectedPeers)
    {
        struct _rgcp_peer_connection *pConn = LIST_ENTRY(pCurr, struct _rgcp_peer_connection, m_listEntry);
        assert(pConn);
        
        if (!pConn->m_bEstablished)
            continue;
        
        fdCount++;
        pollFds = realloc(pollFds, fdCount * sizeof(struct pollfd));
        struct pollfd *poll = &(pollFds[fdCount - 1]);
        poll->fd = pConn->m_remoteFd;
        poll->events = POLLIN;
        poll->revents = 0;
    }

    if (poll(pollFds, fdCount, 0) < 0)
    {
        pthread_mutex_unlock(&pSocket->m_peerData.m_peerMtx);
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    ssize_t dataCount = 0;
    for (ssize_t i = 0; i < fdCount; i++)
    {
        if (pollFds[i].revents & POLLIN)
        {
            uint32_t expectedBufflen = 0;
            if (recv(pollFds[i].fd, &expectedBufflen, sizeof(uint32_t), 0) <= 0)
                continue;

            log_msg("[Lib] Expect %lu bytes from peer %d (poll return: %u)\n", expectedBufflen, pollFds[i].fd, pollFds[i].revents);

            uint8_t* pBuff = calloc(expectedBufflen, sizeof(uint8_t));
            ssize_t recvd_bytes = 0;
            do
            {
                ssize_t recv_res = recv(pollFds[i].fd, pBuff + recvd_bytes, expectedBufflen - recvd_bytes, 0);

                if (recv_res < 0)
                {
                    free(pBuff);
                    continue;
                }

                recvd_bytes += recv_res;
            } while(recvd_bytes != expectedBufflen);

            dataCount++;
            (*ppRecvDataList) = realloc((*ppRecvDataList), sizeof(rgcp_recv_data_t) * dataCount);
            rgcp_recv_data_t *pData = &((*ppRecvDataList)[dataCount - 1]);
            pData->m_bufferSize = expectedBufflen;
            pData->m_pDataBuffer = calloc(expectedBufflen, sizeof(uint8_t));
            pData->m_sourceFd = pollFds[i].fd;

            log_msg("[Lib][%d] Read buffer (%lu bytes, peer %d)\n", pSocket->m_RGCPSocketFd, expectedBufflen, pollFds[i].fd);

            memcpy(pData->m_pDataBuffer, pBuff, expectedBufflen);
            free(pBuff);
        }
    }

    free(pollFds);
    pthread_mutex_unlock(&pSocket->m_peerData.m_peerMtx);
    pthread_mutex_unlock(&pSocket->m_socketMtx);
    return dataCount;
}

void rgcp_free_recv_data(rgcp_recv_data_t* p_recvdatalist, ssize_t data_count)
{
    for (ssize_t i = 0; i < data_count; i++)
        free(p_recvdatalist[i].m_pDataBuffer);

    free(p_recvdatalist);
}
