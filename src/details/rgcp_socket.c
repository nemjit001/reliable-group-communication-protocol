#include "rgcp_socket.h"

#include "logger.h"
#include "crc32.h"

#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <poll.h>

#define max(a,b) ( ((a) > (b)) ? (a) : (b) )

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

int _create_listen_socket(int domain, struct sockaddr_in* addrinfo, socklen_t addrlen)
{
    int fd = socket(domain, SOCK_STREAM, IPPROTO_TCP);

    if (fd < 0)
        return -1;
    
    if (bind(fd, (struct sockaddr*)addrinfo, addrlen) < 0)
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

int rgcp_socket_init(rgcp_socket_t* pSocket, int middlewareFd, int domain)
{
    assert(pSocket);
    log_msg("[Lib] Initializing RGCP Socket @ %p\n", (void*)pSocket);

    if (domain != AF_INET && domain != AF_INET6)
        return -1;

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
        pSocket->m_listenSocketInfo.m_hostAdressLength
    );

    if (pSocket->m_listenSocketInfo.m_listenSocket < 0)
    {
        close(pSocket->m_middlewareFd);
        return -1;
    }

    pSocket->m_helperThreadInfo.m_bShutdownFlag = 0;

    if (pipe(pSocket->m_helperThreadInfo.m_helperThreadPipe) < 0)
    {
        close(pSocket->m_middlewareFd);
        close(pSocket->m_listenSocketInfo.m_listenSocket);
        return -1;
    }

    if (pthread_mutex_init(&pSocket->m_helperThreadInfo.m_communicationMtx, NULL) < 0)
    {
        close(pSocket->m_helperThreadInfo.m_helperThreadPipe[0]);
        close(pSocket->m_helperThreadInfo.m_helperThreadPipe[1]);
        close(pSocket->m_middlewareFd);
        close(pSocket->m_listenSocketInfo.m_listenSocket);
        return -1;
    }

    pSocket->m_helperThreadInfo.m_bMiddlewareHasData = 0;
    if (pthread_cond_init(&pSocket->m_helperThreadInfo.m_bMiddlewareHasDataCond, NULL) < 0)
    {
        close(pSocket->m_helperThreadInfo.m_helperThreadPipe[0]);
        close(pSocket->m_helperThreadInfo.m_helperThreadPipe[1]);
        close(pSocket->m_middlewareFd);
        close(pSocket->m_listenSocketInfo.m_listenSocket);
        pthread_mutex_destroy(&pSocket->m_helperThreadInfo.m_communicationMtx);
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
        return -1;
    }

    list_init(&(pSocket->m_peerData.m_connectedPeers));
    if (pthread_mutex_init(&(pSocket->m_peerData.m_peerMtx), NULL) < 0)
    {
        close(pSocket->m_helperThreadInfo.m_helperThreadPipe[0]);
        close(pSocket->m_helperThreadInfo.m_helperThreadPipe[1]);
        close(pSocket->m_listenSocketInfo.m_listenSocket);
        close(pSocket->m_middlewareFd);
        pthread_cond_destroy(&pSocket->m_helperThreadInfo.m_bMiddlewareHasDataCond);
        pthread_mutex_destroy(&pSocket->m_helperThreadInfo.m_communicationMtx);
        return -1;
    }

    pSocket->m_pSelf = pSocket;

    pthread_mutex_lock(&g_socketListMtx);
    list_add_tail(&pSocket->m_listEntry, &g_rgcpSocketList);
    pthread_mutex_unlock(&g_socketListMtx);

    return 0;
}

void rgcp_socket_free(rgcp_socket_t* pSocket)
{
    log_msg("[Lib] Freeing RGCP Socket @ %p\n", (void*)pSocket);
    
    pSocket->m_helperThreadInfo.m_bShutdownFlag = 1;

    pthread_mutex_destroy(&pSocket->m_helperThreadInfo.m_communicationMtx);
    pthread_cond_destroy(&pSocket->m_helperThreadInfo.m_bMiddlewareHasDataCond);
    pthread_join(pSocket->m_helperThreadInfo.m_communicationThreadHandle, NULL);

    pthread_mutex_destroy(&(pSocket->m_peerData.m_peerMtx));

    close(pSocket->m_helperThreadInfo.m_helperThreadPipe[0]);
    close(pSocket->m_helperThreadInfo.m_helperThreadPipe[1]);

    close(pSocket->m_middlewareFd);
    close(pSocket->m_listenSocketInfo.m_listenSocket);
    
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

void* rgcp_socket_helper_thread(void* pSocketInfo)
{
    rgcp_socket_t* pSocket = (rgcp_socket_t*)pSocketInfo;
    assert(pSocket->m_pSelf == pSocket);

    if (pSocket->m_pSelf != pSocket)
        return NULL;

    struct pollfd remoteFd;
    remoteFd.fd = pSocket->m_middlewareFd;
    remoteFd.events = POLLIN;
    remoteFd.revents = 0;

    while(pSocket->m_helperThreadInfo.m_bShutdownFlag == 0)
    {
        if (poll(&remoteFd, 1, 0) < 0)
        {
            // FIXME: socket in error state
        }

        if (remoteFd.revents & POLLIN)
        {
            struct rgcp_packet* pPacket = NULL;

            if (rgcp_api_recv(pSocket->m_middlewareFd, &pPacket) < 0)
            {
                // FIXME: socket in error state, do error handling
            }

            log_msg("[Lib][%p] Received Middleware Packet (%d, %d, %u)\n", (void*)pSocket, pPacket->m_packetType, pPacket->m_packetError, pPacket->m_dataLen);

            if (rgcp_should_handle_as_helper(pPacket->m_packetType))
            {
                // FIXME: do error handling here
                rgcp_helper_handle_packet(pPacket);
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
        return 0;
    case RGCP_TYPE_PEER_SHARE:
    case RGCP_TYPE_PEER_REMOVE:
        return 1;
    default:
        break;
    }

    return 1;
}

int rgcp_helper_handle_packet(struct rgcp_packet* pPacket)
{
    // TODO: handle packet
    switch (pPacket->m_packetType)
    {
    case RGCP_TYPE_PEER_SHARE:
        {
            // TODO: deserialize packet data and add peer
            // rgcp_socket_add_peer(peerInfo);
        }
        break;
    case RGCP_TYPE_PEER_REMOVE:
        {
            // TODO: deserialize packet data and remove peer
            // rgcp_socket_remove_peer(peerInfo);
        }
        break;
    default:
        break;
    }

    return -1;
}

int rgcp_helper_recv(rgcp_socket_t* pSocket, struct rgcp_packet** ppPacket, time_t timeoutMS)
{
    assert(pSocket);
    assert(ppPacket);
    assert(timeoutMS >= 0);

    if (!pSocket || !ppPacket || timeoutMS < 0)
        return -1;

    pthread_mutex_lock(&pSocket->m_helperThreadInfo.m_communicationMtx);

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
    while(!(pSocket->m_helperThreadInfo.m_bMiddlewareHasData) && rc == 0)
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

    if (read(pSocket->m_helperThreadInfo.m_helperThreadPipe[0], pBuffer, ptrSize) < 0)
        goto error;

    if (pBuffer == NULL)
        goto error;

    *ppPacket = (struct rgcp_packet*)(pBuffer);

    uint32_t packetHash = CRC32_STR_DYNAMIC((char*)pBuffer, ptrSize);
    assert((*ppPacket)->m_packetHash == packetHash);

    if ((*ppPacket)->m_packetHash != packetHash)
        goto error;

    pSocket->m_helperThreadInfo.m_bMiddlewareHasData = 0;
    pthread_mutex_unlock(&pSocket->m_helperThreadInfo.m_communicationMtx);
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

    if (!pSocket || !pPacket)
        return -1;

    pthread_mutex_lock(&pSocket->m_helperThreadInfo.m_communicationMtx);
    
    uint32_t ptrSize = (sizeof(struct rgcp_packet) + pPacket->m_dataLen);
    uint8_t* pBuffer = NULL;
    pBuffer = calloc(ptrSize, sizeof(uint8_t));

    if (pBuffer == NULL)
        return -1;

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