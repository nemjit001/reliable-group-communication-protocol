#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <rgcp/rgcp.h>

#include <pthread.h>

#include "ErrorReport.h"

#define GROUP_NAME_A "A_MULTI_GROUP_TEST"
#define GROUP_NAME_B "B_MULTI_GROUP_TEST_ALTERNATE"

int main()
{
    struct sockaddr_in mwAddr;
    mwAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    mwAddr.sin_port = htons(8000);
    mwAddr.sin_family = AF_INET;

    int fd = rgcp_socket(AF_INET, (struct sockaddr*)&mwAddr, sizeof(mwAddr));

    if (fd < 0)
        ErrorReport("Socket init failed");

    if (rgcp_create_group(fd, GROUP_NAME_A, strlen(GROUP_NAME_A)) < 0)
    {
        rgcp_close(fd);
        ErrorReport("Group A creation failed");
    }

    if (rgcp_create_group(fd, GROUP_NAME_B, strlen(GROUP_NAME_B)) < 0)
    {
        rgcp_close(fd);
        ErrorReport("Group B creation failed");
    }

    rgcp_group_info_t **ppGroupInfos;
    size_t groupCount = rgcp_discover_groups(fd, &ppGroupInfos);
    if  (groupCount < 0)
    {
        rgcp_close(fd);
        ErrorReport("Group discover Failed");
    }

    rgcp_free_group_infos(&ppGroupInfos, groupCount);
    rgcp_close(fd);

    return 0;
}