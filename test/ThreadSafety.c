#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <rgcp/rgcp.h>

#include <pthread.h>

#include "ErrorReport.h"

#define GROUP_NAME "THREAD_SAFETY_TEST"

void* test_thread(void *args)
{
    int fd = *(int*)args;

    rgcp_group_info_t **ppGroupInfos = NULL;
    ssize_t groupCount = rgcp_discover_groups(fd, &ppGroupInfos);

    rgcp_group_info_t* pGroupInfo = NULL;
    int bSuccess = 0;
    uint32_t maxHash = 0;
    for (ssize_t i = 0; i < groupCount; i++)
    {
        if (strcmp(ppGroupInfos[i]->m_pGroupName, GROUP_NAME) == 0 && ppGroupInfos[i]->m_groupNameHash > maxHash)
        {
            maxHash = ppGroupInfos[i]->m_groupNameHash;
            pGroupInfo = ppGroupInfos[i];
            bSuccess = 1;
        }
    }

    if (rgcp_connect(fd, *pGroupInfo) < 0)
        bSuccess = 0;

    if (rgcp_is_connected(fd))
        bSuccess = 1;

    rgcp_free_group_infos(&ppGroupInfos, groupCount);

    int *pSuccess = malloc(sizeof(int));
    *pSuccess = bSuccess;

    return pSuccess;
}

int main(int argc, char** argv)
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

    pthread_t helperThread = -1;
    pthread_create(&helperThread, NULL, test_thread, &fd);

    rgcp_group_info_t **ppGroupInfos = NULL;
    ssize_t groupCount = rgcp_discover_groups(fd, &ppGroupInfos);

    rgcp_group_info_t* pGroupInfo = NULL;
    int bSuccess = 0;
    uint32_t maxHash = 0;
    for (ssize_t i = 0; i < groupCount; i++)
    {
        if (strcmp(ppGroupInfos[i]->m_pGroupName, GROUP_NAME) == 0 && ppGroupInfos[i]->m_groupNameHash > maxHash)
        {
            maxHash = ppGroupInfos[i]->m_groupNameHash;
            pGroupInfo = ppGroupInfos[i];
            bSuccess = 1;
        }
    }

    if (rgcp_connect(fd, *pGroupInfo) < 0)
        bSuccess = 0;

    if (rgcp_is_connected(fd))
        bSuccess = 1;

    rgcp_free_group_infos(&ppGroupInfos, groupCount);

    int *threadSuccess = NULL;
    pthread_join(helperThread, (void**)&threadSuccess);

    if (rgcp_disconnect(fd) < 0)
        bSuccess = 0;

    rgcp_close(fd);

    if (!bSuccess || !threadSuccess)
    {
        free(threadSuccess);
        return -1;
    }
    free(threadSuccess);

    return 0;
}
