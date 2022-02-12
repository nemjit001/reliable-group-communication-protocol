#ifndef RGCP_SOCKET
#define RGCP_SOCKET

#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "linked_list.h"

typedef struct _rgcp_socket_t
{
    struct list_entry m_listEntry;
    int m_socketFd;
    int m_middlewareFd;

    struct
    {
        pthread_mutex_t m_communicationMtx;
        int m_shutdownFlag;
        pthread_t m_communicationThreadHandle;

    } m_helperThreadInfo;

    struct
    {
        struct sockaddr_in m_hostAdress;
        socklen_t m_hostAdressLength;
        int m_listenSocket;
    } m_listenSocketInfo;

    struct _rgcp_socket_t* m_pSelf;
} rgcp_socket_t;

int rgcp_socket_init(rgcp_socket_t* pSocket, int middlewareFd, int domain);

void rgcp_socket_free(rgcp_socket_t* pSocket);

void* rgcp_socket_helper_thread(void* pSocketInfo);

#endif
