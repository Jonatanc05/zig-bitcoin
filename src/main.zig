const std = @import("std");
const FieldElementLib = @import("finite-field.zig");
const FieldElement = FieldElementLib.FieldElement;
const NumberType = FieldElementLib.NumberType;
const fe = FieldElementLib.fieldElementShortcut;
const CurvePoint = @import("elliptic-curve.zig").CurvePoint;
const CryptLib = @import("crypt.zig");
const print = std.debug.print;

pub fn main() !void {
    print("\n------------- FiniteFields -------------\n", .{});
    {
        FieldElementLib.setGlobalPrime(13);
        const a = fe(10);
        const b = fe(5);
        print("Element a: {}\n", .{a});
        print("Element b: {}\n", .{b});
        print("a + b: {}\n", .{a.add(b)});
        print("a - b: {}\n", .{a.sub(b)});
        print("b - a: {}\n", .{b.sub(a)});
        print("a * b: {}\n", .{a.mul(b)});
        print("a ** 2: {}\n", .{a.pow(2)});
        print("a ** 3: {}\n", .{a.pow(3)});
        print("a / b: {}\n", .{a.div(b)});
        print("\n", .{});
    }

    print("------------- EllipticCurves -------------\n", .{});
    {
        FieldElementLib.setGlobalPrime(223);
        const a = fe(0);
        const b = fe(7);
        const p1 = CurvePoint.init(fe(192), fe(105), a, b);
        const p2 = CurvePoint.init(fe(17), fe(56), a, b);
        print("Point p1: {}\n", .{p1});
        print("Point p2: {}\n", .{p2});
        print("p1 + p2: {}\n", .{p1.add(p2)});
        const p3 = CurvePoint.init(fe(47), fe(71), a, b);
        print("Point p3: {}\n", .{p3});
        print("p3 + p3: {}\n", .{p3.add(p3)});
        print("2 p3: {}\n", .{p3.muli(2)});
        print("3 p3: {}\n", .{p3.muli(3)});
        print("18 p3: {}\n", .{p3.muli(18)});
        print("19 p3: {}\n", .{p3.muli(19)});
        print("20 p3: {}\n", .{p3.muli(20)});
        print("21 p3: {}\n", .{p3.muli(21)});
        var G = CurvePoint.init(fe(15), fe(86), a, b);
        G.computeOrder();
        print("ordem do grupo gerado por {}: {}\n", .{ G, G.order.? });
        print("\n", .{});
    }

    print("-------------- Cryptography --------------\n", .{});
    {
        const message = "The quick brown fox jumps over the lazy dog";
        print("message: \"{s}\"\n", .{message});
        const z = CryptLib.hash(message);
        print("h(message): {x}\n", .{z});
        const keys = CryptLib.generateKeyPair();
        print("Public key: {}\nPrivate key: {x}\n", .{ keys.pubk, keys.prvk });
        print("Signing the message...\n", .{});
        const sig = CryptLib.sign(z, keys.prvk);
        print("Verifying the signature...\n", .{});
        print("valid: {}\n\n", .{CryptLib.verify(z, keys.pubk, sig)});
    }

    print("-------------- Serialization --------------\n", .{});
    {
        const p1 = CryptLib.G.muli(3858);
        print("p1.x: 0x{x:0>64}\n", .{p1.x.?.value});
        print("p1.y: 0x{x:0>64}\n", .{p1.y.?.value});

        var p1_uncompressed: [1 + 2 * @divExact(@typeInfo(NumberType).Int.bits, 8)]u8 = undefined;
        CryptLib.serialize(p1, false, &p1_uncompressed);
        print("serialized(p1): 0x", .{});
        for (p1_uncompressed) |b| {
            print("{x:0>2}", .{b});
        }
        print("\n", .{});

        const p1_uncompressed_parsed = CryptLib.parse(p1_uncompressed[0..]);
        print("parsed(serialized(p1)) == p1: {}\n", .{p1_uncompressed_parsed.eq(p1)});

        var p1_compressed: [1 + @divExact(@typeInfo(NumberType).Int.bits, 8)]u8 = undefined;
        CryptLib.serialize(p1, true, &p1_compressed);
        print("compressed(p1): 0x", .{});
        for (p1_compressed) |b| {
            print("{x:0>2}", .{b});
        }
        print("\n", .{});

        const p1_compressed_parsed = CryptLib.parse(p1_compressed[0..]);
        print("parsed(compressed(p1)) == p1: {}\n", .{p1_compressed_parsed.eq(p1)});
    }
}
