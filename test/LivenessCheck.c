#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <rgcp/rgcp.h>

#include "ErrorReport.h"

int main()
{
    struct sockaddr_in mwAddr;
    mwAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    mwAddr.sin_port = htons(8000);
    mwAddr.sin_family = AF_INET;

    int socket = rgcp_socket(AF_INET, (struct sockaddr*)&mwAddr, sizeof(mwAddr));

    if (socket < 0)
        ErrorReport("Socket init failed");

    sleep(70);

    rgcp_group_info_t** ppGroupInfos = NULL;
    ssize_t groupCount = rgcp_discover_groups(socket, &ppGroupInfos);
    if (groupCount < 0)
    {
        rgcp_free_group_infos(&ppGroupInfos, groupCount);
        rgcp_close(socket);
        ErrorReport("Group Discovery Failed");
    }

    rgcp_free_group_infos(&ppGroupInfos, groupCount);
    
    if (rgcp_close(socket) < 0)
    {
        ErrorReport("Closing Socket Failed");
    }

    return 0;
}
