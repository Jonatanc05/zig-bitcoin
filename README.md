## Zig Bitcoin
#### A Bitcoin client with minimal dependencies written in Zig

- I was recently hyped about [handmade software](https://handmade.network/)
- I was recently hyped about [Bitcoin](https://www.reddit.com/r/Bitcoin/comments/1bg5lv0/bitcoin_newcomers_faq_please_read/)
- I was recently hyped about [Zig](https://ziglang.org/)

So I'm following [Jimmy Song's book](https://duckduckgo.com/?q=programming+bitcoin+jimmy+song&t=newext&atb=v407-1&ia=web) to have some hands-on experience with these topics. Note that it's a learning project not meant for any real use, although I would like to use it some day.

---

Currently it's a CLI program with no input and the following output:

```
------------- FiniteFields -------------
Element a: 10_F13
Element b: 5_F13
a + b: 2_F13
a - b: 5_F13
b - a: 8_F13
a * b: 11_F13
a ** 2: 9_F13
a ** 3: 12_F13
a / b: 2_F13

------------- EllipticCurves -------------
Point p1: (c0, 69)
Point p2: (11, 38)
p1 + p2: (aa, 8e)
Point p3: (2f, 47)
p3 + p3: (24, 6f)
2 p3: (24, 6f)
3 p3: (f, 89)
18 p3: (f, 56)
19 p3: (24, 70)
20 p3: (2f, 98)
21 p3: (inf, inf)
ordem do grupo gerado por (f, 56): 7

-------------- Cryptography --------------
message: "The quick brown fox jumps over the lazy dog"
h(message): d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
Public key: (a8e877cddfa3672295b8661048a924a98c6a87186dd4421a223611eb74005c78, 12547c43bb039ea5de023cee885cbbd6e444a0a4c04da402863b64a1d4b958da)
Private key: dc59596ebc49da3f64558bd07b6fadc86814ae72691bd1e230df6689179e1b25
Signing the message...
Verifying the signature...
valid: true

-------------- Serialization --------------
p1.x: 0x8b1d28e29c07f93e00531b199c5db7e053a8be9507c35a8b0b4a3536192a281e
p1.y: 0x1fdd88952ef28c81369cf00a7204d9d08cf58d38c0f97ec124a893b8c98d3516
serialized(p1): 0x048b1d28e29c07f93e00531b199c5db7e053a8be9507c35a8b0b4a3536192a281e1fdd88952ef28c81369cf00a7204d9d08cf58d38c0f97ec124a893b8c98d3516
parsed(serialized(p1)) == p1: true
compressed(p1): 0x028b1d28e29c07f93e00531b199c5db7e053a8be9507c35a8b0b4a3536192a281e
parsed(compressed(p1)) == p1: true

u8_array: { 0, 0, 4, 9, 10, 15, 26, 255 }
base58Encode(u8_array): 131Yr1PVY

------------ Generating BTC Address ------------
testnet: false
prvkey: f45e6907b16670196e487cf667e9fa510f0593276335da22311eb67c90d46421
pubkey (SEC compressed): { 2, 9a, df, 93, 12, f8, f1, 2c, 38, 66, ee, ca, 8b, 8f, 71, 61, 9c, de, cf, e7, f9, 6f, cb, f0, 85, 1c, 95, ca, 5, 79, 11, 7a, 1b }
address: 1EezQQaRpZ6K5LnhiGn8L6vSuWpFHrqvFr

------------------- Transactions -------------------
transaction: crypt.Tx{ .version = 1, .inputs = { crypt.TxInput{ .txid = 28636405658344580202443952903644473261407019314280778112116486762997828230779, .index = 0, .script_sig = { ... }, .sequence = 4294967295 } }, .outputs = { crypt.TxOutput{ .amount = 4999990000, .scri
pt_pubkey = { ... } } }, .locktime = 0 }

------------------- Script -------------------
answer: "And he answering said, Thou shalt love the Lord thy God with all thy heart, and with all thy soul, and with all thy strength, and with all thy mind; and thy neighbour as thyself."
h(answer): { 85, dc, 4b, f5, d3, 8b, 34, 35, f1, f4, 17, 56, 86, b1, 93, fa, 99, b5, ba, eb, 36, 50, 77, d1, 2e, 95, ae, ef, e1, 35, 73, 33 }
script_pub_key: { a8, 20, 85, dc, 4b, f5, d3, 8b, 34, 35, f1, f4, 17, 56, 86, b1, 93, fa, 99, b5, ba, eb, 36, 50, 77, d1, 2e, 95, ae, ef, e1, 35, 73, 33, 87, 69 }
script_sig: { 4c, b2, 41, 6e, 64, 20, 68, 65, 20, 61, 6e, 73, 77, 65, 72, 69, 6e, 67, 20, 73, 61, 69, 64, 2c, 20, 54, 68, 6f, 75, 20, 73, 68, 61, 6c, 74, 20, 6c, 6f, 76, 65, 20, 74, 68, 65, 20, 4c, 6f, 72, 64, 20, 74, 68, 79, 20, 47, 6f, 64, 20, 77, 69, 74, 68, 20, 61, 
6c, 6c, 20, 74, 68, 79, 20, 68, 65, 61, 72, 74, 2c, 20, 61, 6e, 64, 20, 77, 69, 74, 68, 20, 61, 6c, 6c, 20, 74, 68, 79, 20, 73, 6f, 75, 6c, 2c, 20, 61, 6e, 64, 20, 77, 69, 74, 68, 20, 61, 6c, 6c, 20, 74, 68, 79, 20, 73, 74, 72, 65, 6e, 67, 74, 68, 2c, 20, 61, 6e, 64, 20
, 77, 69, 74, 68, 20, 61, 6c, 6c, 20, 74, 68, 79, 20, 6d, 69, 6e, 64, 3b, 20, 61, 6e, 64, 20, 74, 68, 79, 20, 6e, 65, 69, 67, 68, 62, 6f, 75, 72, 20, 61, 73, 20, 74, 68, 79, 73, 65, 6c, 66, 2e }
valid: true

```

---

Currently building with Zig 0.12.0
Windows 11 and Ubuntu WSL are usually tested.
