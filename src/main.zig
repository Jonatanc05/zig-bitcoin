const std = @import("std");
const print = std.debug.print;

const EllipticCurveLib = @import("elliptic-curve.zig");
const FieldElement = EllipticCurveLib.FieldElement;
const NumberType = EllipticCurveLib.NumberType;
const fe = EllipticCurveLib.fieldElementShortcut;
const CurvePoint = EllipticCurveLib.CurvePoint;

const CryptLib = @import("crypt.zig");

pub fn main() !void {
    //    print("\n------------- FiniteFields -------------\n", .{});
    //    {
    //        EllipticCurveLib.setGlobalPrime(13);
    //        const a = fe(10);
    //        const b = fe(5);
    //        print("Element a: {}\n", .{a});
    //        print("Element b: {}\n", .{b});
    //        print("a + b: {}\n", .{a.add(b)});
    //        print("a - b: {}\n", .{a.sub(b)});
    //        print("b - a: {}\n", .{b.sub(a)});
    //        print("a * b: {}\n", .{a.mul(b)});
    //        print("a ** 2: {}\n", .{a.pow(2)});
    //        print("a ** 3: {}\n", .{a.pow(3)});
    //        print("a / b: {}\n", .{a.div(b)});
    //        print("\n", .{});
    //    }
    //
    //    print("------------- EllipticCurves -------------\n", .{});
    //    {
    //        EllipticCurveLib.setGlobalPrime(223);
    //        const a = fe(0);
    //        const b = fe(7);
    //        const p1 = CurvePoint.init(fe(192), fe(105), a, b);
    //        const p2 = CurvePoint.init(fe(17), fe(56), a, b);
    //        print("Point p1: {}\n", .{p1});
    //        print("Point p2: {}\n", .{p2});
    //        print("p1 + p2: {}\n", .{p1.add(p2)});
    //        const p3 = CurvePoint.init(fe(47), fe(71), a, b);
    //        print("Point p3: {}\n", .{p3});
    //        print("p3 + p3: {}\n", .{p3.add(p3)});
    //        print("2 p3: {}\n", .{p3.muli(2)});
    //        print("3 p3: {}\n", .{p3.muli(3)});
    //        print("18 p3: {}\n", .{p3.muli(18)});
    //        print("19 p3: {}\n", .{p3.muli(19)});
    //        print("20 p3: {}\n", .{p3.muli(20)});
    //        print("21 p3: {}\n", .{p3.muli(21)});
    //        var G = CurvePoint.init(fe(15), fe(86), a, b);
    //        G.computeOrder();
    //        print("ordem do grupo gerado por {}: {}\n", .{ G, G.order.? });
    //        print("\n", .{});
    //    }
    //
    //    print("-------------- Cryptography --------------\n", .{});
    //    {
    //        const message = "The quick brown fox jumps over the lazy dog";
    //        print("message: \"{s}\"\n", .{message});
    //        const z = CryptLib.hash(message);
    //        print("h(message): {x}\n", .{z});
    //        const keys = CryptLib.generateKeyPair();
    //        print("Public key: {}\nPrivate key: {x}\n", .{ keys.pubk, keys.prvk });
    //        print("Signing the message...\n", .{});
    //        const sig = CryptLib.sign(z, keys.prvk);
    //        print("Verifying the signature...\n", .{});
    //        print("valid: {}\n\n", .{CryptLib.verify(z, keys.pubk, sig)});
    //    }
    //
    //    print("-------------- Serialization --------------\n", .{});
    //    {
    //        const p1 = CryptLib.G.muli(3858);
    //        print("p1.x: 0x{x:0>64}\n", .{p1.x.?.value});
    //        print("p1.y: 0x{x:0>64}\n", .{p1.y.?.value});
    //
    //        var p1_uncompressed: [1 + 2 * @divExact(@typeInfo(NumberType).Int.bits, 8)]u8 = undefined;
    //        CryptLib.serializePoint(p1, false, &p1_uncompressed);
    //        print("serialized(p1): 0x", .{});
    //        for (p1_uncompressed) |b| {
    //            print("{x:0>2}", .{b});
    //        }
    //        print("\n", .{});
    //
    //        const p1_uncompressed_parsed = CryptLib.parsePoint(p1_uncompressed[0..]);
    //        print("parsed(serialized(p1)) == p1: {}\n", .{p1_uncompressed_parsed.eq(p1)});
    //
    //        var p1_compressed: [1 + @divExact(@typeInfo(NumberType).Int.bits, 8)]u8 = undefined;
    //        CryptLib.serializePoint(p1, true, &p1_compressed);
    //        print("compressed(p1): 0x", .{});
    //        for (p1_compressed) |b| {
    //            print("{x:0>2}", .{b});
    //        }
    //        print("\n", .{});
    //
    //        const p1_compressed_parsed = CryptLib.parsePoint(p1_compressed[0..]);
    //        print("parsed(compressed(p1)) == p1: {}\n", .{p1_compressed_parsed.eq(p1)});
    //
    //        const u8_array = [8]u8{ 0x00, 0x00, 0x04, 0x09, 0x0a, 0x0f, 0x1a, 0xff };
    //        print("\nu8_array: {any}\n", .{u8_array});
    //        var encoded_u8_array: [10]u8 = undefined;
    //        const start = CryptLib.base58Encode(&u8_array, &encoded_u8_array);
    //        print("base58Encode(u8_array): {s}\n\n", .{encoded_u8_array[start..]});
    //    }
    //
    //    print("------------ Generating BTC Address ------------\n", .{});
    //    {
    //        const testnet = false;
    //        print("testnet: {}\n", .{testnet});
    //        const prvk = 0xF45E6907B16670196E487CF667E9FA510F0593276335DA22311EB67C90D46421;
    //        print("prvkey: {x}\n", .{prvk});
    //        const pubk = CryptLib.G.muli(prvk);
    //        var serialized_pubk: [33]u8 = undefined;
    //        CryptLib.serializePoint(pubk, true, &serialized_pubk);
    //        print("pubkey (SEC compressed): {x}\n", .{serialized_pubk});
    //        var address: [40]u8 = undefined;
    //        const start = CryptLib.btcAddress(pubk, &address[0..], testnet);
    //        print("address: {s}\n", .{address[start..]});
    //    }
    //
    //    print("\n------------------- Transactions -------------------\n", .{});
    //    {
    //        // zig fmt: off
    //        var transaction_bytes = [_]u8{
    //            0x01, 0x00, 0x00, 0x00, // version (constant)
    //            0x01, // number of inputs
    //                // 32 bytes of TXID
    //                0x7b, 0x1e, 0xab, 0xe0, 0x20, 0x9b, 0x1f, 0xe7, 0x94, 0x12, 0x45, 0x75, 0xef, 0x80, 0x70, 0x57, 0xc7, 0x7a, 0xda, 0x21, 0x38, 0xae, 0x4f, 0xa8, 0xd6, 0xc4, 0xde, 0x03, 0x98, 0xa1, 0x4f, 0x3f,
    //                0x00, 0x00, 0x00, 0x00, // output index
    //                0x49, // bytes of script signature
    //                    0x48, 0x30, 0x45, 0x02, 0x21, 0x00, 0x89, 0x49, 0xf0, 0xcb, 0x40, 0x00, 0x94, 0xad, 0x2b, 0x5e, 0xb3, 0x99, 0xd5, 0x9d, 0x01, 0xc1, 0x4d, 0x73, 0xd8, 0xfe, 0x6e, 0x96, 0xdf, 0x1a, 0x71, 0x50, 0xde, 0xb3, 0x88, 0xab, 0x89, 0x35, 0x02, 0x20, 0x79, 0x65, 0x60, 0x90, 0xd7, 0xf6, 0xba, 0xc4, 0xc9, 0xa9, 0x4e, 0x0a, 0xad, 0x31, 0x1a, 0x42, 0x68, 0xe0, 0x82, 0xa7, 0x25, 0xf8, 0xae, 0xae, 0x05, 0x73, 0xfb, 0x12, 0xff, 0x86, 0x6a, 0x5f, 0x01,
    //                0xff, 0xff, 0xff, 0xff, // sequence
    //            0x01, // number of outputs
    //                0xf0, 0xca, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, // amount
    //                0x19, // bytes of script pubkey
    //                    0x76, 0xa9, 0x14, 0xcb, 0xc2, 0x0a, 0x76, 0x64, 0xf2, 0xf6, 0x9e, 0x53, 0x55, 0xaa, 0x42, 0x70, 0x45, 0xbc, 0x15, 0xe7, 0xc6, 0xc7, 0x72, 0x88, 0xac,
    //            0x00, 0x00, 0x00, 0x00 // locktime
    //        };
    //        // zig fmt: on
    //        const transaction = try CryptLib.parseTx(transaction_bytes[0..transaction_bytes.len]);
    //        print("transaction: {any}\n", .{transaction});
    //    }
    //
    print("\n------------------- Script -------------------\n", .{});
    {
        const answer = "And he answering said, Thou shalt love the Lord thy God with all thy heart, and with all thy soul, and with all thy strength, and with all thy mind; and thy neighbour as thyself.";
        print("answer: \"{s}\"\n", .{answer});
        const answer_hash = answer_hash: {
            var buf: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(answer, &buf, .{});
            break :answer_hash buf;
        };
        print("h(answer): {x}\n", .{answer_hash});
        const L = CryptLib;
        const script_pub_key = [_]u8{L.OP_SHA256} ++ [1]u8{answer_hash.len} ++ answer_hash ++ [_]u8{ L.OP_EQUAL, L.OP_VERIFY };
        print("script_pub_key: {x}\n", .{script_pub_key});
        const script_sig = [_]u8{L.OP_PUSHDATA1} ++ [1]u8{answer.len} ++ answer.*;
        print("script_sig: {x}\n", .{script_sig});
        const valid = CryptLib.validateScript(&script_sig, &script_pub_key);
        print("valid: {any}\n", .{valid});
    }
}
