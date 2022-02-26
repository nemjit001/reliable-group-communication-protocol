#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <rgcp/rgcp.h>

#include <pthread.h>

#include "ErrorReport.h"

#define GROUP_NAME "MULTI_CLIENT_TEST"

void* test_thread(__attribute__((unused)) void *args)
{
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
        ErrorReport("Group Discover Failed");
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
        ErrorReport("Group Connect Failed");
    }

    sleep(30);
    
    if (rgcp_disconnect(fd) < 0)
    {
        rgcp_free_group_infos(&ppGroups, groupCount);
        rgcp_close(fd);
        ErrorReport("Group Disconnect Failed");
    }

    rgcp_free_group_infos(&ppGroups, groupCount);
    rgcp_close(fd);

    return NULL;
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
    for (int i = 0; i < 3; i++)
        pthread_create(&helper_threads[i], NULL, test_thread, NULL);

    for (int i = 0; i < 3; i++)
        pthread_join(helper_threads[i], NULL);

    rgcp_close(fd);

    return 0;
}
