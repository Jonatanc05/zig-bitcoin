const std = @import("std");
const stdprint = std.debug.print;
const Sha256 = std.crypto.hash.sha2.Sha256;

const EllipticCurveLib = @import("elliptic-curve.zig");
const fe = EllipticCurveLib.FieldElement(u256).fieldElementShortcut;
const CurvePoint = EllipticCurveLib.CurvePoint(u256);
const Bitcoin = @import("bitcoin.zig");

const CryptLib = @import("cryptography.zig");

pub fn print(privkey: u256) !void {
    stdprint("\n------------- FiniteFields -------------\n", .{});
    {
        EllipticCurveLib.FieldElement(u256).setGlobalPrime(13);
        const a = fe(10);
        const b = fe(5);
        stdprint("Element a: {}\n", .{a});
        stdprint("Element b: {}\n", .{b});
        stdprint("a + b: {}\n", .{a.add(b)});
        stdprint("a - b: {}\n", .{a.sub(b)});
        stdprint("b - a: {}\n", .{b.sub(a)});
        stdprint("a * b: {}\n", .{a.mul(b)});
        stdprint("a ** 2: {}\n", .{a.pow(2)});
        stdprint("a ** 3: {}\n", .{a.pow(3)});
        stdprint("a / b: {}\n", .{a.div(b)});
        stdprint("\n", .{});
    }

    stdprint("------------- EllipticCurves -------------\n", .{});
    {
        EllipticCurveLib.FieldElement(u256).setGlobalPrime(223);
        const a = fe(0);
        const b = fe(7);
        const p1 = CurvePoint.init(fe(192), fe(105), a, b);
        const p2 = CurvePoint.init(fe(17), fe(56), a, b);
        stdprint("Point p1: {}\n", .{p1});
        stdprint("Point p2: {}\n", .{p2});
        stdprint("p1 + p2: {}\n", .{p1.add(p2)});
        const p3 = CurvePoint.init(fe(47), fe(71), a, b);
        stdprint("Point p3: {}\n", .{p3});
        stdprint("p3 + p3: {}\n", .{p3.add(p3)});
        stdprint("2 p3: {}\n", .{p3.muli(2)});
        stdprint("3 p3: {}\n", .{p3.muli(3)});
        stdprint("18 p3: {}\n", .{p3.muli(18)});
        stdprint("19 p3: {}\n", .{p3.muli(19)});
        stdprint("20 p3: {}\n", .{p3.muli(20)});
        stdprint("21 p3: {}\n", .{p3.muli(21)});
        var G = CurvePoint.init(fe(15), fe(86), a, b);
        G.computeOrder();
        stdprint("order of the group generated by {}: {}\n", .{ G, G.order.? });
        stdprint("\n", .{});
    }

    stdprint("-------------- Cryptography --------------\n", .{});
    {
        const message = "The quick brown fox jumps over the lazy dog";
        stdprint("message: \"{s}\"\n", .{message});
        const z = CryptLib.hashAsU256(message);
        stdprint("h(message): {x}\n", .{z});
        const keys = CryptLib.generateKeyPair();
        stdprint("Public key: {}\nPrivate key: {x}\n", .{ keys.pubk, keys.prvk });
        stdprint("Signing the message...\n", .{});
        const sig = CryptLib.sign(z, keys.prvk);
        stdprint("Verifying the signature...\n", .{});
        stdprint("valid: {}\n\n", .{CryptLib.verify(z, keys.pubk, sig)});
    }

    stdprint("-------------- Serialization --------------\n", .{});
    {
        const p1 = CryptLib.G.muli(3858);
        stdprint("p1.x: 0x{x:0>64}\n", .{p1.x.?.value});
        stdprint("p1.y: 0x{x:0>64}\n", .{p1.y.?.value});

        var p1_uncompressed: [65]u8 = undefined;
        p1.serialize(false, &p1_uncompressed);
        stdprint("serialized(p1): 0x", .{});
        for (p1_uncompressed) |b| {
            stdprint("{x:0>2}", .{b});
        }
        stdprint("\n", .{});

        const p1_uncompressed_parsed = CurvePoint.parse(p1_uncompressed[0..], CryptLib.secp256k1_p, CryptLib.G.a, CryptLib.G.b);
        stdprint("parsed(serialized(p1)) == p1: {}\n", .{p1_uncompressed_parsed.eq(p1)});

        var p1_compressed: [33]u8 = undefined;
        p1.serialize(true, &p1_compressed);
        stdprint("compressed(p1): 0x", .{});
        for (p1_compressed) |b| {
            stdprint("{x:0>2}", .{b});
        }
        stdprint("\n", .{});

        const p1_compressed_parsed = CurvePoint.parse(p1_compressed[0..], CryptLib.secp256k1_p, CryptLib.G.a, CryptLib.G.b);
        stdprint("parsed(compressed(p1)) == p1: {}\n", .{p1_compressed_parsed.eq(p1)});

        const u8_array = [_]u8{ 0x00, 0x00, 0x04, 0x09, 0x0a, 0x0f, 0x1a, 0xff };
        stdprint("\nu8_array: {x}\n", .{u8_array});
        var encoded: [10]u8 = undefined;
        const start = Bitcoin.Base58.encode(&u8_array, &encoded);
        stdprint("Base58.encode(u8_array): {s}\n", .{encoded[start..]});
        var decoded: [128]u8 = undefined;
        const start_d = Bitcoin.Base58.decode(encoded[start..], &decoded);
        stdprint("Base58.decode(encoded): {x}\n", .{decoded[start_d..]});
        stdprint("Decoded equals original: {}\n\n", .{std.mem.eql(u8, decoded[start_d..], u8_array[2..])});
    }

    stdprint("------------ Generating BTC Address ------------\n", .{});
    {
        const testnet = true;
        stdprint("testnet: {}\n", .{testnet});
        const prvk = 0xF45E6907B16670196E487CF667E9FA510F0593276335DA22311EB67C90D46421;
        stdprint("prvkey: {x}\n", .{prvk});
        const pubk = CryptLib.G.muli(prvk);
        var serialized_pubk: [33]u8 = undefined;
        pubk.serialize(true, &serialized_pubk);
        stdprint("pubkey (SEC compressed): {x}\n", .{serialized_pubk});
        var address: [40]u8 = undefined;
        const start = Bitcoin.Address.fromPubkey(pubk, testnet, address[0..]);
        stdprint("address: {s}\n", .{address[start..]});
    }

    stdprint("\n------------------- Transactions -------------------\n", .{});
    {
        stdprint("\n-----> Serialization\n", .{});
        {
            // zig fmt: off
            var transaction_bytes = [_]u8{
                0x01, 0x00, 0x00, 0x00, // version (constant)
                0x01, // number of inputs
                    // 32 bytes of TXID
                    0x7b, 0x1e, 0xab, 0xe0, 0x20, 0x9b, 0x1f, 0xe7, 0x94, 0x12, 0x45, 0x75, 0xef, 0x80, 0x70, 0x57, 0xc7, 0x7a, 0xda, 0x21, 0x38, 0xae, 0x4f, 0xa8, 0xd6, 0xc4, 0xde, 0x03, 0x98, 0xa1, 0x4f, 0x3f,
                    0x00, 0x00, 0x00, 0x00, // output index
                    0x49, // bytes of script signature
                        0x48, 0x30, 0x45, 0x02, 0x21, 0x00, 0x89, 0x49, 0xf0, 0xcb, 0x40, 0x00, 0x94, 0xad, 0x2b, 0x5e, 0xb3, 0x99, 0xd5, 0x9d, 0x01, 0xc1, 0x4d, 0x73, 0xd8, 0xfe, 0x6e, 0x96, 0xdf, 0x1a, 0x71, 0x50, 0xde, 0xb3, 0x88, 0xab, 0x89, 0x35, 0x02, 0x20, 0x79, 0x65, 0x60, 0x90, 0xd7, 0xf6, 0xba, 0xc4, 0xc9, 0xa9, 0x4e, 0x0a, 0xad, 0x31, 0x1a, 0x42, 0x68, 0xe0, 0x82, 0xa7, 0x25, 0xf8, 0xae, 0xae, 0x05, 0x73, 0xfb, 0x12, 0xff, 0x86, 0x6a, 0x5f, 0x01,
                    0xff, 0xff, 0xff, 0xff, // sequence
                0x01, // number of outputs
                    0xf0, 0xca, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, // amount
                    0x19, // bytes of script pubkey
                        0x76, 0xa9, 0x14, 0xcb, 0xc2, 0x0a, 0x76, 0x64, 0xf2, 0xf6, 0x9e, 0x53, 0x55, 0xaa, 0x42, 0x70, 0x45, 0xbc, 0x15, 0xe7, 0xc6, 0xc7, 0x72, 0x88, 0xac,
                0x00, 0x00, 0x00, 0x00 // locktime
            };
            // zig fmt: on
            const transaction = try Bitcoin.Tx.parse(transaction_bytes[0..transaction_bytes.len]);
            defer transaction.deinit();
            stdprint("{any}\n", .{transaction});
        }

        stdprint("\n-----> Serialization SegWit (a real transaction on https://mempool.space/signet/tx/bd9d8ea4a30d9465159f199c48acda11441d8bcd66020ad55a1215015431bb18)\n", .{});
        {
            // zig fmt: off
            var transaction_bytes = [_]u8{
                0x02, 0x00, 0x00, 0x00,
                0x00, 0x01, // witness marker and flag
                0x01,
                    0x28, 0xae, 0x67, 0x25, 0x22, 0x1f, 0xc3, 0x11, 0x91, 0x26, 0x09, 0xd2, 0xc3, 0x43, 0x50, 0x0f, 0x63, 0x35, 0x10, 0x65, 0xab, 0x59, 0xca, 0xf5, 0xc3, 0x16, 0x38, 0x66, 0x21, 0x77, 0xea, 0xdc,
                    0x01, 0x00, 0x00, 0x00,
                    0x00,
                    0xfd, 0xff, 0xff, 0xff,
                0x02,
                    0x19, 0xcf, 0x0b, 0x44, 0x3a, 0x00, 0x00, 0x00,
                    0x22,   0x51, 0x20, 0xaa, 0xc3, 0x5f, 0xe9, 0x1f, 0x20, 0xd4, 0x88, 0x16, 0xb3, 0xc8, 0x30, 0x11, 0xd1, 0x17, 0xef, 0xa3, 0x5a, 0xcd, 0x24, 0x14, 0xd3, 0x6c, 0x1e, 0x02, 0xb0, 0xf2, 0x9f, 0xc3, 0x10, 0x6d, 0x90,

                    0x80, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x16,   0x00, 0x14, 0xbf, 0x9d, 0x74, 0xa5, 0x0e, 0x3b, 0x9c, 0x9a, 0xca, 0x37, 0x08, 0xca, 0x95, 0x14, 0x19, 0xbb, 0xd6, 0xfa, 0x32, 0x63,
                // witness
                0x01, 0x40, 0x66, 0xbb, 0xff, 0xd4, 0xda, 0xfd, 0x01, 0x72, 0x83, 0xa7, 0x13, 0x2e, 0xff, 0x9f, 0x70, 0xf1, 0xec, 0xbc, 0x5c, 0x66, 0x38, 0xc3, 0x1b, 0x75, 0x6e, 0x61, 0xa6, 0xa6, 0x3e, 0x07, 0x2f, 0xe6, 0xf5, 0x4a, 0xc4, 0xfd, 0x69, 0xa4, 0x06, 0x10, 0xdf, 0x05, 0xef, 0xbf, 0x08, 0xa7, 0x3b, 0xb5, 0x85, 0x22, 0x7c, 0xd7, 0x5d, 0x99, 0xb5, 0xa8, 0xd3, 0x54, 0x1b, 0xc1, 0x04, 0xe5, 0x10, 0x50,
                0x00, 0x00, 0x00, 0x00 // locktime
            };
            // zig fmt: on
            const transaction = try Bitcoin.Tx.parse(transaction_bytes[0..transaction_bytes.len]);
            defer transaction.deinit();
            stdprint("{any}\n", .{transaction});
        }

        stdprint("\n-----> Script\n", .{});
        {
            const answer = "And he answering said, Thou shalt love the Lord thy God with all thy heart, and with all thy soul, and with all thy strength, and with all thy mind; and thy neighbour as thyself.";
            stdprint("answer: \"{s}\"\n", .{answer});
            const answer_hash = answer_hash: {
                var buf: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(answer, &buf, .{});
                break :answer_hash buf;
            };
            const Op = Bitcoin.Script.Opcode;
            const script_pub_key = [_]u8{Op.OP_SHA256} ++ [1]u8{answer_hash.len} ++ answer_hash ++ [_]u8{ Op.OP_EQUAL, Op.OP_VERIFY };
            stdprint("script_pub_key: OP_SHA256, <Sha256(answer)>, OP_EQUAL, OP_VERIFY\n", .{});
            stdprint("script_pub_key in hex: ", .{});
            for (script_pub_key) |b| stdprint("{x:0>2}", .{b});
            stdprint("\n", .{});
            const script_sig = [_]u8{Op.OP_PUSHDATA1} ++ [1]u8{answer.len} ++ answer.*;
            stdprint("script_sig: OP_PUSHDATA1, <answer>\n", .{});
            stdprint("script_sig in hex: ", .{});
            for (script_sig) |b| stdprint("{x:0>2}", .{b});
            stdprint("\n", .{});
            const valid = Bitcoin.Script.validate(&script_sig, &script_pub_key, null, null);
            stdprint("valid: {any}\n", .{valid});
        }

        stdprint("\n-----> Signing a transaction\n", .{});
        {
            const pubk = CryptLib.G.muli(privkey);
            var pubk_serialized: [33]u8 = undefined;
            pubk.serialize(true, &pubk_serialized);
            const prev_txid = 0x38067470a9a51bea07c1f8b7f51d75d521b57ca9c9d1bf68a2467efe79971fd2;
            const prev_script_pubkey = [_]u8{ 0x76, 0xa9, 0x14, 0xaf, 0x72, 0x4f, 0xc6, 0x1f, 0x4d, 0x5c, 0x4d, 0xb0, 0x6b, 0x33, 0x95, 0xc9, 0xb4, 0x50, 0xa8, 0x0d, 0x25, 0xb6, 0x73, 0x88, 0xac };
            const target_address = "mnvfTUzPbeWBxwxinm37C1bsQ5ckZuN9E7";

            var transaction = try Bitcoin.Tx.initP2PKH(true, prev_txid, 1, 5000, target_address);
            defer transaction.deinit();

            try transaction.sign(privkey, 0, &prev_script_pubkey);

            const serialized = try transaction.serialize();
            stdprint("entire transaction: ", .{});
            for (serialized) |b| stdprint("{x:0>2}", .{b});
            stdprint("\n", .{});

            stdprint("\nNote that the above transaction (with a different signature, of course) was successfully broadcasted to signet with the TXID d5cf8e758abc178121736c9cbb0defe075ef50da4dfb4e736b19f2a2ff66dd14\n", .{});

            stdprint("\n-----> Validating transaction signature\n", .{});
            const checksig = try Bitcoin.Tx.checksig(
                &transaction,
                0,
                &pubk_serialized,
                transaction.inputs[0].script_sig[1..][0..(transaction.inputs[0].script_sig[0])],
                //transaction.witness.?[0], // or above
                &prev_script_pubkey,
            );
            stdprint("OP_CHECKSIG result: {s}\n", .{if (checksig) "valid" else "invalid"});
        }
    }
}