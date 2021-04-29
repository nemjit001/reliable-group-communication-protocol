# Relibale Group Communication Protocol

The Reliable Group Communication Protocol is a highly reliable group to group communication protocol.
The document below details some of the internal workings of the RGCP.

RGCP sits between the application and internet protocol layer of the netstack:

```text
+---------------------+
|     higher-level    |
+---------------------+
|        RGCP         |
+---------------------+
|  internet protocol  |
+---------------------+
|communication network|
+---------------------+
```

## Packet Structure

```text
In Group packet
         0                   1                   2                   3
bit      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                               |                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

```text
Group to Group packet
         0                   1                   2                   3
bit      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                               |                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## State Machine

```text
```
