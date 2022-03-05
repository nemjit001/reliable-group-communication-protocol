#ifndef RGCP_SOCKET
#define RGCP_SOCKET

#define _GNU_SOURCE

#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "details/linked_list.h"
#include "rgcp_peer.h"
#include "rgcp_api.h"

struct _rgcp_peer_connection
{
    struct list_entry m_listEntry;
    int m_remoteFd;
    int m_bEstablished;

    struct _rgcp_peer_info m_peerInfo;
};

typedef struct _rgcp_socket_t
{
    struct list_entry m_listEntry;
    int m_RGCPSocketFd;
    int m_middlewareFd;
    // TODO: fix this -> int m_bErrorState;
    time_t m_heartbeatPeriod;
    pthread_mutex_t m_socketMtx;

    struct
    {
        int m_bShutdownFlag;
        pthread_t m_communicationThreadHandle;
        pthread_mutex_t m_communicationMtx;
        int m_bMiddlewareHasData;
        pthread_cond_t m_bMiddlewareHasDataCond;

        int m_helperThreadPipe[2];
    } m_helperThreadInfo;

    struct
    {
        pthread_mutex_t m_sendMtx;
        pthread_mutex_t m_recvMtx;
    } m_apiMtxes;

    struct
    {
        struct sockaddr_in m_hostAdress;
        socklen_t m_hostAdressLength;
        int m_listenSocket;
    } m_listenSocketInfo;

    struct
    {
        int m_bConnectedToGroup;
        struct list_entry m_connectedPeers;
        pthread_mutex_t m_peerMtx;
    } m_peerData;

    struct _rgcp_socket_t* m_pSelf;
} rgcp_socket_t;

int rgcp_socket_init(rgcp_socket_t* pSocket, int middlewareFd, int domain, time_t heartbeatPeriodSeconds);

void rgcp_socket_free(rgcp_socket_t* pSocket);

int rgcp_socket_get(int sockfd, rgcp_socket_t** ppSocket);

int rgcp_socket_connect_to_peer(rgcp_socket_t* pSocket, struct _rgcp_peer_info peerInfo);

void* rgcp_socket_helper_thread(void* pSocketInfo);

int rgcp_should_handle_as_helper(enum RGCP_PACKET_TYPE packetType);

int rgcp_helper_handle_packet(rgcp_socket_t* pSocket, struct rgcp_packet* pPacket);

int rgcp_add_peer(rgcp_socket_t *pSocket, struct _rgcp_peer_info peerInfo);

int rgcp_remove_peer(rgcp_socket_t *pSocket, struct _rgcp_peer_info peerInfo);

int rgcp_helper_recv(rgcp_socket_t* pSocket, struct rgcp_packet** ppPacket, time_t timeoutMS);

int rgcp_helper_send(rgcp_socket_t* pSocket, struct rgcp_packet* pPacket);

#endif
