#include "rgcp_socket.h"

#include "logger.h"
#include "rgcp_crc32.h"

#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include <netinet/tcp.h>

#define max(a,b) ( ((a) > (b)) ? (a) : (b) )

static pthread_mutex_t g_socketInitMtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_socketListMtx = PTHREAD_MUTEX_INITIALIZER;
LIST_HEAD(g_rgcpSocketList);

int _get_next_fd()
{
    int maxFd = 0;

    struct list_entry* pCurr, * pNext;
    LIST_FOR_EACH(pCurr, pNext, &g_rgcpSocketList)
    {
        rgcp_socket_t* pSocket = LIST_ENTRY(pCurr, rgcp_socket_t, m_listEntry);
        maxFd = max(pSocket->m_RGCPSocketFd, maxFd) + 1;
    }
    
    return maxFd;
}

int _create_listen_socket(int domain, struct sockaddr_in* addrinfo, socklen_t *addrlen)
{
    int fd = socket(domain, SOCK_STREAM, IPPROTO_TCP);

    if (fd < 0)
        return -1;
    
    if (bind(fd, (struct sockaddr*)addrinfo, *addrlen) < 0)
    {
        close(fd);
        return -1;
    }

    if (getsockname(fd, (struct sockaddr*)addrinfo, addrlen) < 0)
    {
        close(fd);
        return -1;
    }

    if (listen(fd, SOMAXCONN) < 0)
    {
        close(fd);
        return -1;
    }

    return fd;
}

int _send_heartbeat(rgcp_socket_t* pSocket)
{
    struct rgcp_packet *pHeartbeatPacket = NULL;
    if (rgcp_packet_init(&pHeartbeatPacket, 0) < 0)
    {
        pthread_mutex_unlock(&pSocket->m_socketMtx);
        return -1;
    }

    if (rgcp_api_send(pSocket->m_middlewareFd, &pSocket->m_apiMtxes.m_sendMtx, pHeartbeatPacket) < 0)
    {
        // FIXME: socket in error state
    }

    rgcp_packet_free(pHeartbeatPacket);
    return 0;
}

int rgcp_socket_init(rgcp_socket_t* pSocket, int middlewareFd, int domain, time_t heartbeatPeriodSeconds)
{
    assert(pSocket);

    if (domain != AF_INET && domain != AF_INET6)
        return -1;

    pthread_mutex_lock(&g_socketInitMtx);

    pSocket->m_heartbeatPeriod = heartbeatPeriodSeconds;
    pSocket->m_middlewareFd = middlewareFd;
    pSocket->m_RGCPSocketFd = _get_next_fd();

    pSocket->m_listenSocketInfo.m_hostAdress.sin_addr.s_addr = INADDR_ANY;
    pSocket->m_listenSocketInfo.m_hostAdress.sin_port = 0;
    pSocket->m_listenSocketInfo.m_hostAdress.sin_family = domain;

    pSocket->m_listenSocketInfo.m_hostAdressLength = sizeof(pSocket->m_listenSocketInfo.m_hostAdress);
    pSocket->m_listenSocketInfo.m_listenSocket = -1;

    pSocket->m_listenSocketInfo.m_listenSocket = _create_listen_socket(
        domain, 
        &pSocket->m_listenSocketInfo.m_hostAdress, 
        &pSocket->m_listenSocketInfo.m_hostAdressLength
    );

    pSocket->m_peerData.m_bConnectedToGroup = 0;
    pSocket->m_pSelf = pSocket;
    pSocket->m_helperThreadInfo.m_bShutdownFlag = 0;
    pSocket->m_helperThreadInfo.m_bMiddlewareHasData = 0;
    list_init(&pSocket->m_peerData.m_connectedPeers);

    if (pSocket->m_listenSocketInfo.m_listenSocket < 0)
    {
        pthread_mutex_unlock(&g_socketInitMtx);
        return -1;
    }

    if (pthread_mutex_init(&pSocket->m_socketMtx, NULL) < 0)
    {
        close(pSocket->m_listenSocketInfo.m_listenSocket);
        pthread_mutex_unlock(&g_socketInitMtx);
        return -1;
    }

    if (pthread_mutex_init(&pSocket->m_apiMtxes.m_sendMtx, NULL) < 0)
    {
        close(pSocket->m_listenSocketInfo.m_listenSocket);
        pthread_mutex_unlock(&g_socketInitMtx);
        return -1;
    }

    if (pthread_mutex_init(&pSocket->m_apiMtxes.m_recvMtx, NULL) < 0)
    {
        close(pSocket->m_listenSocketInfo.m_listenSocket);
        pthread_mutex_unlock(&g_socketInitMtx);
        return -1;
    }

    if (pSocket->m_listenSocketInfo.m_listenSocket < 0)
    {
        close(pSocket->m_middlewareFd);
        pthread_mutex_unlock(&g_socketInitMtx);
        return -1;
    }

    if (pipe(pSocket->m_helperThreadInfo.m_helperThreadPipe) < 0)
    {
        close(pSocket->m_middlewareFd);
        close(pSocket->m_listenSocketInfo.m_listenSocket);
        pthread_mutex_unlock(&g_socketInitMtx);
        return -1;
    }

    if (pthread_mutex_init(&pSocket->m_helperThreadInfo.m_communicationMtx, NULL) < 0)
    {
        close(pSocket->m_helperThreadInfo.m_helperThreadPipe[0]);
        close(pSocket->m_helperThreadInfo.m_helperThreadPipe[1]);
        close(pSocket->m_middlewareFd);
        close(pSocket->m_listenSocketInfo.m_listenSocket);
        pthread_mutex_unlock(&g_socketInitMtx);
        return -1;
    }

    if (pthread_cond_init(&pSocket->m_helperThreadInfo.m_bMiddlewareHasDataCond, NULL) < 0)
    {
        close(pSocket->m_helperThreadInfo.m_helperThreadPipe[0]);
        close(pSocket->m_helperThreadInfo.m_helperThreadPipe[1]);
        close(pSocket->m_middlewareFd);
        close(pSocket->m_listenSocketInfo.m_listenSocket);
        pthread_mutex_destroy(&pSocket->m_helperThreadInfo.m_communicationMtx);
        pthread_mutex_unlock(&g_socketInitMtx);
        return -1;
    }

    if (pthread_create(&pSocket->m_helperThreadInfo.m_communicationThreadHandle, NULL, rgcp_socket_helper_thread, (void*)pSocket) < 0)
    {
        close(pSocket->m_helperThreadInfo.m_helperThreadPipe[0]);
        close(pSocket->m_helperThreadInfo.m_helperThreadPipe[1]);
        close(pSocket->m_listenSocketInfo.m_listenSocket);
        close(pSocket->m_middlewareFd);
        pthread_cond_destroy(&pSocket->m_helperThreadInfo.m_bMiddlewareHasDataCond);
        pthread_mutex_destroy(&pSocket->m_helperThreadInfo.m_communicationMtx);
        pthread_mutex_unlock(&g_socketInitMtx);
        return -1;
    }

    if (pthread_mutex_init(&(pSocket->m_peerData.m_peerMtx), NULL) < 0)
    {
        close(pSocket->m_helperThreadInfo.m_helperThreadPipe[0]);
        close(pSocket->m_helperThreadInfo.m_helperThreadPipe[1]);
        close(pSocket->m_listenSocketInfo.m_listenSocket);
        close(pSocket->m_middlewareFd);
        pthread_cond_destroy(&pSocket->m_helperThreadInfo.m_bMiddlewareHasDataCond);
        pthread_mutex_destroy(&pSocket->m_helperThreadInfo.m_communicationMtx);
        pthread_mutex_unlock(&g_socketInitMtx);
        return -1;
    }

    pthread_mutex_lock(&g_socketListMtx);
    list_add_tail(&pSocket->m_listEntry, &g_rgcpSocketList);
    pthread_mutex_unlock(&g_socketListMtx);
    
    pthread_mutex_unlock(&g_socketInitMtx);

    log_msg("[Lib] Initializing RGCP Socket [%d] @ %p\n", pSocket->m_RGCPSocketFd, (void*)pSocket);

    return 0;
}

void rgcp_socket_free(rgcp_socket_t* pSocket)
{
    log_msg("[Lib] Freeing RGCP Socket @ %p\n", (void*)pSocket);
    
    pSocket->m_helperThreadInfo.m_bShutdownFlag = 1;

    pthread_mutex_destroy(&pSocket->m_socketMtx);
    pthread_mutex_destroy(&pSocket->m_helperThreadInfo.m_communicationMtx);
    pthread_cond_destroy(&pSocket->m_helperThreadInfo.m_bMiddlewareHasDataCond);
    pthread_join(pSocket->m_helperThreadInfo.m_communicationThreadHandle, NULL);

    pthread_mutex_destroy(&(pSocket->m_peerData.m_peerMtx));

    close(pSocket->m_helperThreadInfo.m_helperThreadPipe[0]);
    close(pSocket->m_helperThreadInfo.m_helperThreadPipe[1]);

    shutdown(pSocket->m_middlewareFd, SHUT_RDWR);
    close(pSocket->m_middlewareFd);

    close(pSocket->m_listenSocketInfo.m_listenSocket);

    struct list_entry *pCurr, *pNext;
    LIST_FOR_EACH(pCurr, pNext, &pSocket->m_peerData.m_connectedPeers)
    {
        struct _rgcp_peer_connection *pCurrPeer = LIST_ENTRY(pCurr, struct _rgcp_peer_connection, m_listEntry);
        if (pCurrPeer->m_remoteFd > 0)
            close(pCurrPeer->m_remoteFd);
        
        free(pCurrPeer);
    }
    
    pthread_mutex_lock(&g_socketListMtx);
    list_del(&pSocket->m_listEntry);
    pthread_mutex_unlock(&g_socketListMtx);
}

int rgcp_socket_get(int sockfd, rgcp_socket_t** ppSocket)
{
    pthread_mutex_lock(&g_socketListMtx);

    struct list_entry* pCurr, * pNext;
    LIST_FOR_EACH(pCurr, pNext, &g_rgcpSocketList)
    {
        rgcp_socket_t* pCurrSocket = LIST_ENTRY(pCurr, rgcp_socket_t, m_listEntry);
        assert(pCurrSocket->m_pSelf == pCurrSocket);

        if (pCurrSocket->m_RGCPSocketFd == sockfd)
        {
            (*ppSocket) = pCurrSocket;
            pthread_mutex_unlock(&g_socketListMtx);
            return 0;
        }
    }

    pthread_mutex_unlock(&g_socketListMtx);
    return -1;
}

int rgcp_socket_connect_to_peer(rgcp_socket_t* pSocket, struct _rgcp_peer_info peerInfo)
{
    log_msg("[Lib][%d] Connecting to peer socket\n", pSocket->m_RGCPSocketFd);

    pthread_mutex_lock(&pSocket->m_peerData.m_peerMtx);

    struct _rgcp_peer_connection * pConnection = calloc(1, sizeof(struct _rgcp_peer_connection));
    pConnection->m_peerInfo = peerInfo;
    pConnection->m_remoteFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    pConnection->m_bEstablished = 0;

    if (connect(pConnection->m_remoteFd, (struct sockaddr*)&peerInfo.m_addressInfo, peerInfo.m_addressLength) < 0)
        goto error;

    int enable = 1;
    if (setsockopt(pConnection->m_remoteFd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(int)) < 0)
        goto error;

    if (setsockopt(pConnection->m_remoteFd, IPPROTO_TCP, TCP_KEEPIDLE, &enable, sizeof(int)) < 0)
        goto error;

    if (setsockopt(pConnection->m_remoteFd, IPPROTO_TCP, TCP_KEEPINTVL, &enable, sizeof(int)) < 0)
        goto error;
    
    if (setsockopt(pConnection->m_remoteFd, IPPROTO_TCP, TCP_KEEPCNT, &enable, sizeof(int)) < 0)
        goto error;

    pConnection->m_bEstablished = 1;

    list_add_tail(&pConnection->m_listEntry, &pSocket->m_peerData.m_connectedPeers);
    pthread_mutex_unlock(&pSocket->m_peerData.m_peerMtx);
    return 0;

error:
    close(pConnection->m_remoteFd);
    pthread_mutex_unlock(&pSocket->m_peerData.m_peerMtx);
    return -1;
}

void* rgcp_socket_helper_thread(void* pSocketInfo)
{
    rgcp_socket_t* pSocket = (rgcp_socket_t*)pSocketInfo;
    assert(pSocket->m_pSelf == pSocket);

    if (pSocket->m_pSelf != pSocket)
        return NULL;

    struct pollfd remoteFd;
    time_t lastHeartbeatTime = 0, currTime = time(NULL);
    while(pSocket->m_helperThreadInfo.m_bShutdownFlag == 0)
    {
        currTime = time(NULL);
        assert(currTime >= lastHeartbeatTime);
        time_t timeDeltaSeconds = currTime - lastHeartbeatTime;

        if (timeDeltaSeconds >= pSocket->m_heartbeatPeriod)
        {
            if (_send_heartbeat(pSocket) < 0)
                continue;

            lastHeartbeatTime = currTime;
        }

        memset(&remoteFd, 0, sizeof(struct pollfd));

        remoteFd.fd = pSocket->m_middlewareFd;
        remoteFd.events = POLLIN | POLLRDHUP;
        remoteFd.revents = 0;

        if (poll(&remoteFd, 1, 0) < 0)
        {
            // FIXME: socket in error state
        }

        if (remoteFd.revents & POLLRDHUP)
        {
            // socket in invalid state

            log_msg("[Lib][%d] Middleware closed connection\n", pSocket->m_RGCPSocketFd);
            pSocket->m_helperThreadInfo.m_bShutdownFlag = 1;
            return NULL;
        }
        else if (remoteFd.revents & POLLIN)
        {
            struct rgcp_packet* pPacket = NULL;
            ssize_t bytesReceived = rgcp_api_recv(pSocket->m_middlewareFd, &pSocket->m_apiMtxes.m_recvMtx, &pPacket);

            if (bytesReceived <= 0)
            {
                // FIXME: socket in error state, do error handling
                log_msg("[Lib][%d] Error in API receive (received %d bytes, packet ptr is \"%p\")\n", pSocket->m_RGCPSocketFd, bytesReceived, (void*)pPacket);
                return NULL;
            }

            log_msg("[Lib][%d] Received Middleware Packet (%d, %d, %u)\n", pSocket->m_RGCPSocketFd, pPacket->m_packetType, pPacket->m_packetError, pPacket->m_dataLen);

            if (rgcp_should_handle_as_helper(pPacket->m_packetType))
            {
                // FIXME: do error handling here
                rgcp_helper_handle_packet(pSocket, pPacket);
            }
            else
            {
                // FIXME: do error handling here
                rgcp_helper_send(pSocket, pPacket);
            }
            
            rgcp_packet_free(pPacket);
        }
    }

    return NULL;
}

int rgcp_should_handle_as_helper(enum RGCP_PACKET_TYPE packetType)
{
    // NOTE: No error checking is done here yet. If an invalid packet type is specified, the packet is handled by the helper thread and discarded.

    switch (packetType)
    {
    case RGCP_TYPE_GROUP_DISCOVER_RESPONSE:
    case RGCP_TYPE_GROUP_CREATE_RESPONSE:
    case RGCP_TYPE_GROUP_JOIN_RESPONSE:
    case RGCP_TYPE_GROUP_LEAVE_RESPONSE:
        return 0;
    case RGCP_TYPE_PEER_SHARE:
    case RGCP_TYPE_PEER_REMOVE:
    case RGCP_TYPE_SOCKET_DISCONNECT_RESPONSE:
        return 1;
    default:
        break;
    }

    return 1;
}

int rgcp_helper_handle_packet(rgcp_socket_t* pSocket, struct rgcp_packet* pPacket)
{
    switch (pPacket->m_packetType)
    {
    case RGCP_TYPE_PEER_SHARE:
        {
            struct _rgcp_peer_info info;
            if (deserialize_rgcp_peer_info(&info, pPacket->m_data, pPacket->m_dataLen) < 0)
                return -1;

            if (rgcp_add_peer(pSocket, info) < 0)
                return -1;
        }
        break;
    case RGCP_TYPE_PEER_REMOVE:
        {
            struct _rgcp_peer_info info;
            if (deserialize_rgcp_peer_info(&info, pPacket->m_data, pPacket->m_dataLen) < 0)
                return -1;

            if (rgcp_remove_peer(pSocket, info) < 0)
                return -1;
        }
        break;
    case RGCP_TYPE_SOCKET_DISCONNECT_RESPONSE:
        {
            pSocket->m_helperThreadInfo.m_bShutdownFlag = 1;
            if (rgcp_helper_send(pSocket, pPacket) < 0)
                return -1;
        }
        break;
    default:
        break;
    }

    return 0;
}

int rgcp_add_peer(rgcp_socket_t *pSocket, struct _rgcp_peer_info peerInfo)
{
    pthread_mutex_lock(&pSocket->m_peerData.m_peerMtx);

    struct _rgcp_peer_connection *pConnection = calloc(1, sizeof(struct _rgcp_peer_connection));

    struct sockaddr_in peerAddr;
    socklen_t addrlen = sizeof(peerAddr);
    int peerFd = accept(pSocket->m_listenSocketInfo.m_listenSocket, (struct sockaddr*)&peerAddr, &addrlen);

    char* peerIpAddr = inet_ntoa(peerInfo.m_addressInfo.sin_addr);

    pConnection->m_peerInfo = peerInfo;
    pConnection->m_remoteFd = -1;
    pConnection->m_bEstablished = 0;

    if (peerInfo.m_addressInfo.sin_addr.s_addr != peerAddr.sin_addr.s_addr)
    {
        log_msg("[Lib][%d] Unexpected address for peer (expected %lu, was %lu)\n", pSocket->m_RGCPSocketFd, peerInfo.m_addressInfo.sin_addr.s_addr, peerAddr.sin_addr.s_addr);
        return -1;
    }

    pConnection->m_bEstablished = 1;
    pConnection->m_remoteFd = peerFd;

    list_add_tail(&pConnection->m_listEntry, &pSocket->m_peerData.m_connectedPeers);

    log_msg("[Lib][Peer][%d] Added peer (%s:%u)\n", pSocket->m_RGCPSocketFd, peerIpAddr, peerInfo.m_addressInfo.sin_port);
    pthread_mutex_unlock(&pSocket->m_peerData.m_peerMtx);
    return 0;
}

int rgcp_remove_peer(rgcp_socket_t *pSocket, struct _rgcp_peer_info peerInfo)
{
    pthread_mutex_lock(&pSocket->m_peerData.m_peerMtx);

    struct list_entry *pCurr, *pNext;
    LIST_FOR_EACH(pCurr, pNext, &pSocket->m_peerData.m_connectedPeers)
    {
        struct _rgcp_peer_connection *pConnection = LIST_ENTRY(pCurr, struct _rgcp_peer_connection, m_listEntry);
        char* peerIpAddr = inet_ntoa(pConnection->m_peerInfo.m_addressInfo.sin_addr);

        if (pConnection->m_peerInfo.m_addressInfo.sin_addr.s_addr == peerInfo.m_addressInfo.sin_addr.s_addr && pConnection->m_peerInfo.m_addressInfo.sin_port == peerInfo.m_addressInfo.sin_port)
        {
            log_msg("[Lib][Peer][%d] Removed peer (%s:%u)\n", pSocket->m_RGCPSocketFd, peerIpAddr, pConnection->m_peerInfo.m_addressInfo.sin_port);

            list_del(pCurr);
            close(pConnection->m_remoteFd);
            free(pConnection);
            break;
        }
    }

    pthread_mutex_unlock(&pSocket->m_peerData.m_peerMtx);
    return 0;
}

int rgcp_helper_recv(rgcp_socket_t* pSocket, struct rgcp_packet** ppPacket, time_t timeoutMS)
{
    assert(pSocket);
    assert(ppPacket);
    assert(timeoutMS >= 0);

    if (!pSocket || !ppPacket || timeoutMS < 0)
        return -1;

    uint32_t ptrSize = 0;
    uint8_t* pBuffer = NULL;

    struct timespec waitTime;
    if (clock_gettime(CLOCK_REALTIME, &waitTime) < 0)
        goto error;
    
    uint32_t timeoutNs = (timeoutMS * 1000000) % 1000000;
    uint32_t timeoutSeconds = (timeoutMS / 1000);

    // set timeout from ms to ns
    waitTime.tv_sec += timeoutSeconds;
    waitTime.tv_nsec += timeoutNs;
    
    int rc = 0;
    while((pSocket->m_helperThreadInfo.m_bMiddlewareHasData == 0) && rc == 0)
        rc = pthread_cond_timedwait(&(pSocket->m_helperThreadInfo.m_bMiddlewareHasDataCond), &(pSocket->m_helperThreadInfo.m_communicationMtx), &waitTime);

    if (rc == ETIMEDOUT)
    {
        errno = ETIMEDOUT;
        return -1;
    }

    if (read(pSocket->m_helperThreadInfo.m_helperThreadPipe[0], &ptrSize, sizeof(uint32_t)) < 0)
        goto error;

    if (ptrSize == 0)
        goto error;

    pBuffer = calloc(ptrSize, sizeof(uint8_t));

    assert(pBuffer);
    if (!pBuffer)
        goto error;

    if (read(pSocket->m_helperThreadInfo.m_helperThreadPipe[0], pBuffer, ptrSize) < 0)
        goto error;

    *ppPacket = (struct rgcp_packet*)(pBuffer);

    uint32_t receivedPacketHash = (*ppPacket)->m_packetHash;
    (*ppPacket)->m_packetHash = 0;
    uint32_t actualPacketHash = RGCP_CRC32_DYNAMIC((uint8_t*)(*ppPacket), ptrSize);

    assert(actualPacketHash == receivedPacketHash);
    if (actualPacketHash != receivedPacketHash)
        goto error;

    pSocket->m_helperThreadInfo.m_bMiddlewareHasData = 0;

    return ptrSize;

error:
    (*ppPacket) = NULL;
    pthread_mutex_unlock(&pSocket->m_helperThreadInfo.m_communicationMtx);
    return -1;
}

int rgcp_helper_send(rgcp_socket_t* pSocket, struct rgcp_packet* pPacket)
{
    assert(pSocket);
    assert(pPacket);
    assert(pSocket->m_helperThreadInfo.m_bMiddlewareHasData == 0);

    if (!pSocket || !pPacket)
        return -1;

    pthread_mutex_lock(&pSocket->m_helperThreadInfo.m_communicationMtx);

    uint32_t ptrSize = (sizeof(struct rgcp_packet) + pPacket->m_dataLen);
    uint8_t* pBuffer = NULL;
    pBuffer = calloc(ptrSize, sizeof(uint8_t));

    if (pBuffer == NULL)
        return -1;

    pPacket->m_packetHash = 0;
    pPacket->m_packetHash = RGCP_CRC32_DYNAMIC((uint8_t*)pPacket, ptrSize);
    memcpy(pBuffer, pPacket, ptrSize);

    if (write(pSocket->m_helperThreadInfo.m_helperThreadPipe[1], &ptrSize, sizeof(uint32_t)) < 0)
    {
        free(pBuffer);
        return -1;
    }
    
    if (write(pSocket->m_helperThreadInfo.m_helperThreadPipe[1], pBuffer, ptrSize) < 0)
    {
        free(pBuffer);
        return -1;
    }

    free(pBuffer);

    pSocket->m_helperThreadInfo.m_bMiddlewareHasData = 1;

    pthread_mutex_unlock(&pSocket->m_helperThreadInfo.m_communicationMtx);
    pthread_cond_broadcast(&(pSocket->m_helperThreadInfo.m_bMiddlewareHasDataCond));

    return 0;
}