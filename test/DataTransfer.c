#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <rgcp/rgcp.h>

#include <pthread.h>

#include "ErrorReport.h"

#define GROUP_NAME "DATA_TRANSFER_TEST"
#define TEST_BUFFER "DATA TEST 123\0"

void* test_thread(void *arg)
{
    int* retval = (int*)arg;

    struct sockaddr_in mwAddr;
    mwAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    mwAddr.sin_port = htons(8000);
    mwAddr.sin_family = AF_INET;

    int fd = rgcp_socket(AF_INET, (struct sockaddr*)&mwAddr, sizeof(mwAddr));

    if (fd < 0)
        ErrorReport("Socket init failed");

    rgcp_group_info_t** ppGroups = NULL;
    ssize_t groupCount = rgcp_discover_groups(fd, &ppGroups);

    if (groupCount < 0)
    {
        rgcp_close(fd);
        perror("Group Discover Failed");
        return NULL;
    }

    rgcp_group_info_t *pTargetGroup = NULL;
    uint32_t maxHash = 0;
    for (ssize_t i = 0; i < groupCount; i++)
    {
        if (strcmp(ppGroups[i]->m_pGroupName, GROUP_NAME) == 0 && ppGroups[i]->m_groupNameHash > maxHash)
        {
            pTargetGroup = ppGroups[i];
        }
    }

    if (rgcp_connect(fd, *pTargetGroup) < 0)
    {
        rgcp_free_group_infos(&ppGroups, groupCount);
        rgcp_close(fd);
        perror("Group Connect Failed");
        *retval = -1;
        return retval;
    }

    rgcp_free_group_infos(&ppGroups, groupCount);

    sleep(5);

    if (rgcp_peer_count(fd) != 2)
    {
        perror("Group Connect not 2");
        *retval = -1;
        return retval;
    }
    
    if (rgcp_send(fd, TEST_BUFFER, strlen(TEST_BUFFER) + 1, RGCP_SEND_BROADCAST) < 0)
    {
        rgcp_free_group_infos(&ppGroups, groupCount);
        rgcp_close(fd);
        perror("Send Failed");
        *retval = -1;
        return retval;
    }

    sleep(5);

    rgcp_recv_data_t* recvDatas = NULL;
    ssize_t recvCount = rgcp_recv(fd, &recvDatas);
    if (recvCount < 0)
    {
        rgcp_close(fd);
        perror("Recv Failed");
        *retval = -1;
        return retval;
    }

    sleep(5);

    if (recvCount != 2)
    {
        rgcp_close(fd);
        perror("Recv Count not 2");
        *retval = -1;
        return retval;
    }

    for (ssize_t i = 0; i < recvCount; i++)
        printf("\t[#%ld @ %d] %s (%ld)\n", i, recvDatas[i].m_sourceFd, recvDatas[i].m_pDataBuffer, recvDatas[i].m_bufferSize);

    if (recvDatas[0].m_bufferSize != recvDatas[1].m_bufferSize || strcmp(recvDatas[0].m_pDataBuffer, recvDatas[1].m_pDataBuffer) != 0)
    {
        rgcp_close(fd);
        perror("Recv Buffers neq");
        *retval = -1;
        return retval;
    }

    if (recvDatas[0].m_sourceFd == recvDatas[1].m_sourceFd)
    {
        rgcp_close(fd);
        perror("Same source on buffers");
        *retval = -1;
        return retval;
    }

    rgcp_free_recv_data(recvDatas, recvCount);
    
    if (rgcp_disconnect(fd) < 0)
    {
        rgcp_close(fd);
        perror("Disconnect Failed");
        *retval = -1;
        return retval;
    }

    rgcp_close(fd);

    return retval;
}

int main()
{
    struct sockaddr_in mwAddr;
    mwAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    mwAddr.sin_port = htons(8000);
    mwAddr.sin_family = AF_INET;

    int fd = rgcp_socket(AF_INET, (struct sockaddr*)&mwAddr, sizeof(mwAddr));

    if (fd < 0)
        ErrorReport("Socket init failed");

    if (rgcp_create_group(fd, GROUP_NAME, strlen(GROUP_NAME)) < 0)
    {
        rgcp_close(fd);
        ErrorReport("Group creation failed");
    }

    pthread_t helper_threads[3];
    int *retvals[3] = { 0, 0, 0 };

    for (int i = 0; i < 3; i++)
    {
        retvals[i] = calloc(1, sizeof(int));
        *(retvals[i]) = 0;
        pthread_create(&helper_threads[i], NULL, test_thread, retvals[i]);
    }


    for (int i = 0; i < 3; i++)
    {
        pthread_join(helper_threads[i], (void**)&retvals[i]);
    }

    rgcp_close(fd);

    int bFailed = 0;
    for (int i = 0; i < 3; i++)
    {
        if (*retvals[i] != 0)
            bFailed = 1;
        
        free(retvals[i]);
    }

    return bFailed ? -1 : 0;
}
