# Relibale Group Communication Protocol

The Reliable Group Communication Protocol is a highly reliable group to group communication protocol.
The document below details some of the internal workings of the RGCP.

RGCP is an application level protocol, facilitating group to group communication through its API.

```text
+---------------------+
|     RGCP            |
+---------------------+
|  Transport Layer    |
+---------------------+
|  internet protocol  |
+---------------------+
|communication network|
+---------------------+
```

## Packet Structure

```text
         0                   1                   2                   3
bit      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                               |                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Middleware

## State Machine

```text
```
