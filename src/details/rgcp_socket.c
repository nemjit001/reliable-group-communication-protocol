#include "rgcp_socket.h"

#include "rgcp_api.h"
#include "logger.h"

#include <assert.h>
#include <unistd.h>

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

    int commSockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, commSockets) < 0)
    {
        close(pSocket->m_middlewareFd);
        close(pSocket->m_listenSocketInfo.m_listenSocket);
        return -1;
    }

    pSocket->m_helperThreadInfo.m_communicationSockets.m_commThreadSocket = commSockets[0];
    pSocket->m_helperThreadInfo.m_communicationSockets.m_mainThreadSocket = commSockets[1];

    if (pthread_mutex_init(&pSocket->m_helperThreadInfo.m_communicationMtx, NULL) < 0)
    {
        close(commSockets[0]);
        close(commSockets[1]);
        close(pSocket->m_middlewareFd);
        close(pSocket->m_listenSocketInfo.m_listenSocket);
        return -1;
    }

    if (pthread_cond_init(&pSocket->m_helperThreadInfo.m_bMiddlewareHasData, NULL) < 0)
    {
        close(commSockets[0]);
        close(commSockets[1]);
        close(pSocket->m_middlewareFd);
        close(pSocket->m_listenSocketInfo.m_listenSocket);
        pthread_mutex_destroy(&pSocket->m_helperThreadInfo.m_communicationMtx);
        return -1;
    }

    if (pthread_create(&pSocket->m_helperThreadInfo.m_communicationThreadHandle, NULL, rgcp_socket_helper_thread, (void*)pSocket) < 0)
    {
        close(commSockets[0]);
        close(commSockets[1]);
        close(pSocket->m_listenSocketInfo.m_listenSocket);
        close(pSocket->m_middlewareFd);
        pthread_cond_destroy(&pSocket->m_helperThreadInfo.m_bMiddlewareHasData);
        pthread_mutex_destroy(&pSocket->m_helperThreadInfo.m_communicationMtx);
        return -1;
    }

    list_init(&(pSocket->m_connectedPeers));

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
    pthread_cond_destroy(&pSocket->m_helperThreadInfo.m_bMiddlewareHasData);
    pthread_join(pSocket->m_helperThreadInfo.m_communicationThreadHandle, NULL);

    close(pSocket->m_helperThreadInfo.m_communicationSockets.m_commThreadSocket);
    close(pSocket->m_helperThreadInfo.m_communicationSockets.m_mainThreadSocket);

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

    while(pSocket->m_helperThreadInfo.m_bShutdownFlag == 0)
    {
        pthread_mutex_lock(&pSocket->m_helperThreadInfo.m_communicationMtx);

        struct rgcp_packet* pPacket = NULL;

        if (rgcp_api_recv(pSocket->m_middlewareFd, &pPacket) < 0)
        {
            // FIXME: socket in error state
        }

        log_msg("[Lib][%p] Received Middleware Packet (%d, %d, %u)\n", (void*)pSocket, pPacket->m_packetType, pPacket->m_packetError, pPacket->m_dataLen);

        // TODO: forward to main thread
        
        rgcp_packet_free(pPacket);

        pthread_mutex_unlock(&pSocket->m_helperThreadInfo.m_communicationMtx);
    }

    return NULL;
}