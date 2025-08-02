## ZiglyNode - Zig Lyght Node

#### A Bitcoin light client with minimal dependencies written in Zig

- I like [handmade software](https://handmade.network/)
- I like [Bitcoin](https://btcmaxis.com/)
- I like [Zig](https://ziglang.org/)

## Build Requirements

- Currently building with Zig 0.14.1

- Windows 11 and Ubuntu WSL are usually tested.

- Before compiling, add a file called `.privkey` to the `src` directory.
    - `echo 0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a > src/.privkey`

This file should contain hex characters representing the private key to use when signing transactions. **DO NOT USE REAL WALLET INFORMATION WITH THIS SOFTWARE**.

## Features

All features here are implemented (at least almost) from scratch. Using only the standard library and an external RIPEMD hash function.

- Amateur cryptography (ECDSA)
- Bitcoin primitives (Address, Transaction, Block) with serialization
- Signing valid transactions (see https://mempool.space/signet/tx/d5cf8e758abc178121736c9cbb0defe075ef50da4dfb4e736b19f2a2ff66dd14)
- Script interpreter (tested P2PK, P2PKH and P2WPKH)
- Ability to communicate with the Bitcoin network
    - Handshake with other peers
    - Get block headers, check they are valid and write/load them on disk
    - Get neighbour peers to discover the network
- Multi-threaded handshakes for speed

## Screenshots

Example of current output:

```
> zig build run
info: loading block headers from path/to/ZiglyNode/blockheaders.dat

Your address is mwWdV8mUAE2rQugQLtRJdrqxi3rf4R3xbq

################################################

Hello dear hodler, tell me what can I do for you
1. List peers (interact)
2. Connect to a new peer
3. View blockchain state
4. Sign a transaction
5. Exit

3

=== Blockchain State ===
Block headers count: 66001
Latest block hash: 00000000071d7e8a0f4895e60c1073df9311d65a85244be1ee6369c9506281af
========================

2

Enter the IPv4 or IPv6 [without port] [default=127.0.0.1]: 
Enter the port [numeric, default=8333]: 

Connection established successfully with
Peer ID: 1
IP: 127.0.0.1:8333

i 1

What do you want to do?
1. disconnect from peer
2. ask for block headers
3. ask for new peers and connect
2
Requesting for block headers...
Unexpected and unsupported command received
Unexpected and unsupported command received
2000 new blocks received!

3

=== Blockchain State ===
Block headers count: 68001
Latest block hash: 0000000000d991791fdfdbccbbc2a73d2f86ccf78e2d0a7ce7675f40b5986b3e
========================

i 1

What do you want to do?
1. disconnect from peer
2. ask for block headers
3. ask for new peers and connect
3
info: Requesting for new peers and connecting...
info: Connected to 5 new peers

################################################

Hello dear hodler, tell me what can I do for you
1. List peers (interact)
2. Connect to a new peer
3. View blockchain state
4. Sign a transaction
5. Exit

1

======== Peer list ========

1: 127.0.0.1:8333 | /Satoshi:27.1.0/Knots:20240801

2: 3.143.194.71:8333 | /Satoshi:27.1.0/

3: 86.104.228.24:8333 | /Satoshi:27.0.0/

4: 170.253.31.42:8333 | /Satoshi:28.1.0/

5: 66.163.223.69:8333 | /Satoshi:27.1.0/

6: [2a02:22a0:bbb3:dc10:50e1:57ff:fe70:9492]:8333 | /Satoshi:29.0.0/

===========================

Type 'i' followed by a number to interact with a peer (ex.: 'i 2')

5
info: saving data on disk...

```

