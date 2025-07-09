## Zig Bitcoin

#### A Bitcoin client with minimal dependencies written in Zig

- I like [handmade software](https://handmade.network/)
- I like [Bitcoin](https://btcmaxis.com/)
- I like [Zig](https://ziglang.org/)

## Build Requirements

- Currently building with Zig 0.14.1

- Windows 11 and Ubuntu WSL are usually tested.

- Before compiling, add a file called `.privkey` to the `src` directory.
    - `echo 0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a > src/.privkey`

This file should contain hex characters representing the private key to use when signing transactions. **DO NOT USE REAL WALLET INFORMATION WITH THIS SOFTWARE**.

## Screenshots

Example of current output:

```
> zig build run

Your address is mwWdV8mUAE2rQugQLtRJdrqxi3rf4R3xbq

################################################

Hello dear hodler, tell me what can I do for you
1. List connections (interact with peers)
2. Connect to a new peer
3. Sign a transaction
4. Exit

2
Enter the IPv4 or IPv6 [without port]: 74.220.255.190
Enter the port [numeric, default=8333]: 
debug: Sending message "version" with following payload (93 bytes):
debug: 62ea0000000000000000000078cb6e6800000000000000000000000000000000000000000000000000000000208d000000000000000000000000000000000000ffff7f000001208d78cb6e6800000000075a69676e6f64650000000000
debug: Received message "version" with the following payload (102 bytes):
debug: 801101000d0400000000000077cb6e6800000000000000000000000000000000000000000000ffffb12710adeda80d040000000000000000000000000000000000000000000000007cbb68171210230d102f5361746f7368693a32352e302e302f5fce0d0001
debug: Received message "verack" with the following payload (0 bytes):
debug:
debug: Sending message "verack" with following payload (0 bytes):
debug:

Connection established successfully with
Peer ID: 1
IP: 74.220.255.190:8333
User Agent: /Satoshi:25.0.0/


################################################

Hello dear hodler, tell me what can I do for you
1. List connections (interact with peers)
2. Connect to a new peer
3. Sign a transaction
4. Exit

i 1

What do you want to do?
1. disconnect from peer
2. ask for block headers
2
Requesting for block headers...
debug: Sending message "getheaders" with following payload (69 bytes):
debug: 62ea0000016fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900000000000000000000000000000000000000000000000000000000000000000000000000
debug: Received message "alert" with the following payload (168 bytes):
debug: 60010000000000000000000000ffffff7f00000000ffffff7ffeffff7f01ffffff7f00000000ffffff7f00ffffff7f002f555247454e543a20416c657274206b657920636f6d70726f6d697365642c207570677261646520726571756972656400463044022065
3febd6410f470f6bae11cad19c48413becb1ac2c17f908fd0fd53bdc3abd5202206d0e9c96fe88d4a0f01ed9dedae2b6f9e00da94cad0fecaae66ecf689bf71b50
debug: Received message "ping" with the following payload (8 bytes):
debug: ee770b9444ddd399
debug: Sending message "pong" with following payload (8 bytes):
debug: ee770b9444ddd399
debug: Received message "headers" with the following payload (162003 bytes):
debug: fdd007010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e3629900010000004860eb18bf1b1620e37e9490fc8a42
7514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd610001000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db
9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d00010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc1
6649ffff001d2bfee0a9000100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e4770001000000fc33f596f822a0a1951ff
dbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c9700010000008d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a03130000000003f674005
103b42f984169c7d008370967e91920a6a5d64fd51282f75bc73a68af1c66649ffff001d39a59c8600010000004494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000e3855ed886605b6d4a99d5fa2ef2e9b0b164e63df3c4136bebf2d0dac0f
1f7a667c86649ffff001d1c4b56660001000000c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37047fca6649ffff001d28404f5300010000000508085c47cc
849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000112ba175a1e04b14ba9e7ea5f76ab640affeef5ec98173ac9799a852fa39add320cd6649ffff001d1e2de5650001000000e915d9a478e3adf3186c07c61a22228b10fd87df343c92782ecc052c0000000
06e06373c80de397406dc3d19c90d71d230058d28293614ea58d6a57f8f5d32f8b8ce6649ffff001d173807f800010000007330d7adf261c69891e6ab08367d957e74d4044bc5d9cd06d656be9700000000b8c8754fabb0ffeb04ca263a1368c39c059ca0d4af3151b876
...
Blocks received (2000):
[0] 00000000839a8e6886ab: PoW OK, prev OK
[1] 000000006a625f06636b: PoW OK, prev OK
[2] 0000000082b5015589a3: PoW OK, prev OK
[3] 000000004ebadb55ee90: PoW OK, prev OK
[4] 000000009b7262315dbf: PoW OK, prev OK
[5] 000000003031a0e73735: PoW OK, prev OK
...


```

