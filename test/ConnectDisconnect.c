#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <rgcp/rgcp.h>

#include "ErrorReport.h"

#define GROUP_NAME_A    "CONNECT_TEST"
#define GROUP_NAME_B    "CONNECT_TEST_ALT"
#define PEERS           10

void close_sockets(int fds[PEERS])
{
    for (int i = 0; i < 5; i++)
        rgcp_close(fds[i]);
}

int main(int argc, char** argv)
{
    struct sockaddr_in mwAddr;
    mwAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    mwAddr.sin_port = htons(8000);
    mwAddr.sin_family = AF_INET;

    int fds[PEERS];
    
    for (int i = 0; i < PEERS; i++)
    {
        fds[i] = rgcp_socket(AF_INET, (struct sockaddr*)&mwAddr, sizeof(mwAddr));
        if (fds[i] < 0)
            ErrorReport("Socket init failed");
    }

    if (rgcp_create_group(fds[0], GROUP_NAME_A, strlen(GROUP_NAME_A)) < 0)
    {
        close_sockets(fds);
        ErrorReport("Group creation 1 failed");
    }

    if (rgcp_create_group(fds[0], GROUP_NAME_B, strlen(GROUP_NAME_B)) < 0)
    {
        close_sockets(fds);
        ErrorReport("Group creation 2 failed");
    }

    rgcp_group_info_t **ppGroupInfos = NULL;
    ssize_t groupcount = rgcp_discover_groups(fds[0], &ppGroupInfos);

    if (groupcount < 0)
    {
        close_sockets(fds);
        ErrorReport("Group discover failed");
    }

    rgcp_group_info_t* pGroupA;
    rgcp_group_info_t* pGroupB;
    uint32_t aMaxHash = 0, bMaxHash = 0;
    for (int i = 0; i < groupcount; i++)
    {
        if (strcmp(ppGroupInfos[i]->m_pGroupName, GROUP_NAME_A) == 0 && ppGroupInfos[i]->m_groupNameHash > aMaxHash)
        {
            pGroupA = ppGroupInfos[i];
        }

        if (strcmp(ppGroupInfos[i]->m_pGroupName, GROUP_NAME_B) == 0 && ppGroupInfos[i]->m_groupNameHash > bMaxHash)
        {
            pGroupB = ppGroupInfos[i];
        }
    }

    for (int i = 0; i < PEERS; i++)
    {
        if (i < (PEERS / 2) + 1)
        {
            rgcp_connect(fds[i], *pGroupA);
        }
        else
        {
            rgcp_connect(fds[i], *pGroupB);
        }
    }

    assert(rgcp_peer_count(fds[0]) == (PEERS / 2));

    if (rgcp_disconnect(fds[0]) < 0)
    {
        close_sockets(fds);
        ErrorReport("Disconnect Failed");
    }

    assert(rgcp_peer_count(fds[0]) == 0);

    if (rgcp_connect(fds[0], *pGroupB) < 0)
    {
        close_sockets(fds);
        ErrorReport("Connect 2 new Failed");
    }

    if (PEERS % 2 == 0)
        assert(rgcp_peer_count(fds[0]) == (PEERS / 2) - 1);
    else
        assert(rgcp_peer_count(fds[0]) == (PEERS / 2));

    close_sockets(fds);

    return 0;
}
