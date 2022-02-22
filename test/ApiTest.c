#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <rgcp/rgcp.h>

#include "ErrorReport.h"

int main()
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

    for (ssize_t i = 0; i < groupCount; i++)
    {
        printf("[%ld] 0x%x %s\n", i, ppGroups[i]->m_groupNameHash, ppGroups[i]->m_pGroupName);
    }

    if (groupCount < 0)
    {
        rgcp_close(fd);
        ErrorReport("Group Discover 1 Failed");
    }

    const char* groupname = "TEST_GROUP";
    if (rgcp_create_group(fd, groupname, strlen(groupname)) < 0)
    {
        rgcp_close(fd);
        ErrorReport("Group Creation Failed");
    }

    ppGroups = NULL;
    groupCount = rgcp_discover_groups(fd, &ppGroups);

    if (groupCount < 0)
        ErrorReport("Group Discover 2 Failed");

    for (ssize_t i = 0; i < groupCount; i++)
    {
        printf("[%ld] 0x%x %s\n", i, ppGroups[i]->m_groupNameHash, ppGroups[i]->m_pGroupName);
    }

    rgcp_group_info_t *pTargetGroup = NULL;
    for (ssize_t i = 0; i < groupCount; i++)
    {
        if (strcmp(ppGroups[i]->m_pGroupName, groupname) == 0)
        {
            pTargetGroup = ppGroups[i];
            break;
        }
    }

    if (rgcp_connect(fd, *pTargetGroup) < 0)
    {
        rgcp_close(fd);
        ErrorReport("Group Connect Failed");
    }
    
    if (rgcp_disconnect(fd) < 0)
    {
        rgcp_close(fd);
        ErrorReport("Group Disconnect Failed");
    }

    rgcp_close(fd);

    return 0;
}
