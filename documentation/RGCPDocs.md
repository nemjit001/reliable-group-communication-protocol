# Reliable Group Communication Protocol

The Reliable Group Communication Protocol is a reliable group communication protocol.
The document below details some of the internal workings of the RGCP.

RGCP is an application level protocol, facilitating group communication through its API.
TCP is used as the backbone of RGCP's communication.

A separate middleware service is required to use RGCP. This middleware service handles group
creation, deletion, join, and leave request. These requests are handled in the order in which
they come in.

## Including the library in your project

The RGCP library is a dynamic library. It can be linked using during
compile time by the name `rgcp`.

To use the RGCP API functions, only the following header file needs
to be included:

```C
<rgcp/rgcp.h>
```

There are more header files available, these expose functions and
structures that are helpful for developing custom middleware
implementations.

These are the following header files:

```C
<rgcp/rgcp_api.h>   // API defines for middleware communication
<rgcp/rgcp_crc32.h> // The crc32 implementation used by RGCP
<rgcp/rgcp_group.h> // Group structures and (de)serialization helpers
<rgcp/rgcp_peer.h>  // Peer structures and (de)serialization helpers
```

## RGCP Defines

All RGCP defines can be configured by defining them before including the
library. This allows some behviour to be customized based on the
programmer's requirements.

### `RGCP_SOCKET_TIMEOUT_MS`

This define determines how long rgcp functions should block until they are
considered timedout. If this timeout is reached before the middleware
provides a response, these functions fail. This define expects a
timeout specified in milliseconds.

### `RGCP_SOCKET_HEARTBEAT_PERIOD_SECONDS`

This define determines how the period by which heartbeat messages are sent
to the middleware service. These heartbeat messages tell the middleware
service that the associated socket is still online. This define
expects a period in seconds.

If you reconfigure this define, ensure that it is either the same or less than the middleware service's heartbeat timeout, otherwise valid
connections will be closed.

## RGCP structures

```C
rgcp_recv_data_t
{
    int m_sourceFd;
    size_t m_bufferSize;
    uint8_t* m_pDataBuffer;
} rgcp_recv_data_t;
```

The `rgcp_recv_data_t` structure contains the source fd of buffers, a
pointer to the buffer, and the total length of the buffer.

```C
rgcp_unicast_mask_t
{
    int m_targetFd;
};
```

The `rgcp_unicast_mask_t` structure contains an integer denoting the
targeted peer. This structure is only used when sending a unicast message.

```C
rgcp_group_info_t
{
    uint32_t m_groupNameHash;
    uint32_t m_groupNameLength;
    char* m_pGroupName;
}
```

The `rgcp_group_info_t` structure contains a group name, the length of the
name string, and the hash of the group name.

## RGCP API functions

Listed below are all available RGCP API functions, grouped by their use.
All RGCP API functions are threadsafe, and no functions will block
indefinitely.

### Socket creation and deletion

```C
int rgcp_socket(int domain, struct sockaddr* middlewareaddr, socklen_t addrlen);
```

The `rgcp_socket(...)` function creates a new RGCP socket.

Arguments:

- domain: an integer, either AF_INET or AF_INET6
- middlewareaddr: a sockaddr pointer, the address of an RGCP middleware service
- addrlen: the size of the struct stored in middlewareaddr

Return:

- On success: a positive integer
- On failure: -1

```C
int rgcp_close(int sockfd);
```

The `rgcp_close(...)` function disconnects and closes an RGCP socket. If the socket is not
connected to a group, it is only closed. Fails if the passed socket does not exist.

Arguments:

- sockfd: an integer, an open RGCP socket

Return:

- On success: 0
- On failure: -1

### Group Discovery

```C
ssize_t rgcp_discover_groups(int sockfd, rgcp_group_info_t*** ppp_group_infos);
```

The `rgcp_discover_groups(...)` function requests a list of groups from the middleware
service. This function blocks until the middleware service has provided the
requested data, or until the timeout `RGCP_SOCKET_TIMEOUT_MS` is reached.

Arguments:

- sockfd: an integer, an open RGCP socket
- ppp_group_infos: a valid pointer to an `rgcp_group_info_t*` pointer, can not
be `NULL`

Return:

- On success: a positive integer denoting the number of groups returned in
`ppp_group_infos`
- On failure: -1

```C
int rgcp_free_group_infos(rgcp_group_info_t*** ppp_group_infos, ssize_t group_count);
```

The `rgcp_free_group_infos(...)` function frees all memory associated with an
array of `group_info_t` pointers.

Arguments:

- ppp_group_infos: a valid pointer to an `rgcp_group_info_t*` pointer, can not
be `NULL`
- group_count: a signed size type, must be greater than 0.

Return:

- On success: 0
- On failure: -1

### Creating a group

```C
int rgcp_create_group(int sockfd, const char* groupname, size_t namelen);
```

The `rgcp_create_group(...)` function forwards a group creation request to the middleware
service. This function blocks until the middleware has provided a response, or until the timeout `RGCP_SOCKET_TIMEOUT_MS` is reached.

Arguments:

- sockfd: an integer, an open RGCP socket
- groupname: a C string, contains the name the newly created group will have. Can not be
`NULL`
- namelen: a size type, the length of the string in `groupname`

Return:

- On success: 0
- On failure: -1

### Managing connection state

```C
int rgcp_connect(int sockfd, rgcp_group_info_t group_info);
```

The `rgcp_connect(...)` function forwards a group connection request to the middleware
service. This function blocks until the middleware has provided a response, or until the timeout `RGCP_SOCKET_TIMEOUT_MS` is reached.

Arguments:

- sockfd: an integer, an open RGCP socket
- group_info, a group info structure

Return:

- On success: 0
- On failure: -1

```C
int rgcp_is_connected(int sockfd);
```

The `rgcp_is_connected(...)` function checks if the passed socket is connected to a group.

Arguments:

- sockfd: an integer, an open  RGCP socket

Return:

- 1 if the passed socket is connected to a group
- 0 if the passed socket is not connected to a group, or if it does not exist

```C
ssize_t rgcp_peer_count(int sockfd);
```

The `rgcp_peer_count(...)` function returns the number of other peers in the group
the passed RGCP socket belongs to.

Arguments:

- sockfd: an integer, an open RGCP socket

Return:

- On success: the number of other peers in the RGCP group `sockfd` belongs to
- On failure: -1

```C
int rgcp_disconnect(int sockfd);
```

The `rgcp_disconnect(...)` function disconnects the passed RGCP socket from the group it
is connected to. If the passed socket is not connected to a group, this function returns
early with a 'success' statuscode. This function blocks until the middleware has provided a
response, or until the timeout `RGCP_SOCKET_TIMEOUT_MS` is reached.

Arguments:

- sockfd: an integer, an open RGCP socket

Return:

- On success: 0
- On failure: -1

### Sending and receiving data

```C
ssize_t rgcp_send(int sockfd, const void* buf, size_t len, enum RGCP_SEND_FLAGS flags, void* p_params);
```

The `rgcp_send(...)` function sends data to other group members. The group is determined by the passed RGCP socket.
The `flags` argument determines the type of communication used. The `p_params` argument allows passing of
extra data if the function requires it. This function blocks until `len` bytes have been sent to all peers.

The available flags for this function are `RGCP_SEND_BROADCAST` and `RGCP_SEND_UNICAST` for broadcast and unicast behaviour respectively.
The `p_params` argument is used in conjunction with the `RGCP_SEND_UNICAST` flag. A `rgcp_unicast_mask_t` structure pointer is passed here when this
flag is set. The `p_params` argument may be `NULL` when the `RGCP_SEND_BROADCAST` flag is used.

Arguments:

- sockfd: an integer, an open RGCP socket
- buf: a void pointer to a data buffer, cannot be `NULL`
- len: size type, the size in bytes to send from `buf`
- flags: RGCP_SEND_FLAGS, one of the valid values from the RGCP_SEND_FLAGS enum
- p_params: a void pointer, either `NULL` or a valid structure needed by `rgcp_send(...)`

Return:

- On success: the total bytes sent to peers
- On failure: -1

```C
ssize_t rgcp_recv(int sockfd, rgcp_recv_data_t** pp_recvdatalist);
```

The `rgcp_recv(...)` function receives all available bytes from all currently connected peers. Connected peers are determined by the group `sockfd`
belongs to. This function blocks until all data has been received.
The returned buffers are stored in an array of `rgcp_recv_data_t` structures. These structures store all needed buffer information.

Arguments:

- sockfd: an integer, an open RGCP socket
- pp_recvdatalist: a pointer to `rgcp_recv_data_t*`, can not be `NULL`

Return:

- On success: the number of `rgcp_recv_data_t` structures returned
- On failure: -1

```C
void rgcp_free_recv_data(rgcp_recv_data_t* p_recvdatalist, ssize_t data_count);
```

The `rgcp_free_recv_data(...)` function frees all memory associated with the passed `rgcp_recv_data_t` array.

Arguments:

- p_recvdatalist: an `rgcp_recv_data_t` array, cannot be `NULL`
- data_count: size type, the number of `rgcp_recv_data_t` structures in `p_recvdatalist`
