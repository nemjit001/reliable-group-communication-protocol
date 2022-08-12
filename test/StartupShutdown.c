#include <arpa/inet.h>
#include <stdlib.h>
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

    rgcp_close(socket);

    return 0;
}
