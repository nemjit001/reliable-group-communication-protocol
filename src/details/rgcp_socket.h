#ifndef RGCP_SOCKET
#define RGCP_SOCKET

#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "linked_list.h"

typedef struct _rgcp_socket_t
{
    struct list_entry m_listEntry;
    int m_RGCPSocketFd;
    int m_middlewareFd;

    struct
    {
        int m_bShutdownFlag;
        pthread_t m_communicationThreadHandle;
        pthread_mutex_t m_communicationMtx;
        pthread_cond_t m_bMiddlewareHasData;

        struct
        {
            int m_commThreadSocket;
            int m_mainThreadSocket;
        } m_communicationSockets;
    } m_helperThreadInfo;

    struct
    {
        struct sockaddr_in m_hostAdress;
        socklen_t m_hostAdressLength;
        int m_listenSocket;
    } m_listenSocketInfo;

    struct list_entry m_connectedPeers;
    struct _rgcp_socket_t* m_pSelf;
} rgcp_socket_t;

int rgcp_socket_init(rgcp_socket_t* pSocket, int middlewareFd, int domain);

void rgcp_socket_free(rgcp_socket_t* pSocket);

int rgcp_socket_get(int sockfd, rgcp_socket_t** ppSocket);

void* rgcp_socket_helper_thread(void* pSocketInfo);

#endif
