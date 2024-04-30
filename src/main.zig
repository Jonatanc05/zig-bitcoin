const std = @import("std");
const FieldElementLib = @import("finite-field.zig");
const FieldElement = FieldElementLib.FieldElement;
const NumberType = FieldElementLib.NumberType;
const fe = FieldElementLib.fieldElementShortcut;
const CurvePoint = @import("elliptic-curve.zig").CurvePoint;
const CryptLib = @import("crypt.zig");

pub fn main() !void {
    std.debug.print("\n------------- FiniteFields -------------\n", .{});
    {
        FieldElementLib.setGlobalPrime(13);
        const a = fe(10);
        const b = fe(5);
        std.debug.print("Element a: {}\n", .{a});
        std.debug.print("Element b: {}\n", .{b});
        std.debug.print("a + b: {}\n", .{a.add(b)});
        std.debug.print("a - b: {}\n", .{a.sub(b)});
        std.debug.print("b - a: {}\n", .{b.sub(a)});
        std.debug.print("a * b: {}\n", .{a.mul(b)});
        std.debug.print("a ** 2: {}\n", .{a.pow(2)});
        std.debug.print("a ** 3: {}\n", .{a.pow(3)});
        std.debug.print("a / b: {}\n", .{a.div(b)});
        std.debug.print("\n", .{});
    }

    std.debug.print("------------- EllipticCurves -------------\n", .{});
    {
        FieldElementLib.setGlobalPrime(223);
        const a = fe(0);
        const b = fe(7);
        const p1 = CurvePoint.init(fe(192), fe(105), a, b);
        const p2 = CurvePoint.init(fe(17), fe(56), a, b);
        std.debug.print("Point p1: {}\n", .{p1});
        std.debug.print("Point p2: {}\n", .{p2});
        std.debug.print("p1 + p2: {}\n", .{p1.add(p2)});
        const p3 = CurvePoint.init(fe(47), fe(71), a, b);
        std.debug.print("Point p3: {}\n", .{p3});
        std.debug.print("p3 + p3: {}\n", .{p3.add(p3)});
        std.debug.print("2 p3: {}\n", .{p3.muli(2)});
        std.debug.print("3 p3: {}\n", .{p3.muli(3)});
        std.debug.print("18 p3: {}\n", .{p3.muli(18)});
        std.debug.print("19 p3: {}\n", .{p3.muli(19)});
        std.debug.print("20 p3: {}\n", .{p3.muli(20)});
        std.debug.print("21 p3: {}\n", .{p3.muli(21)});
        var G = CurvePoint.init(fe(15), fe(86), a, b);
        G.computeOrder();
        std.debug.print("ordem do grupo gerado por {}: {}\n", .{ G, G.order.? });
        std.debug.print("\n", .{});
    }

    std.debug.print("-------------- Cryptography --------------\n", .{});
    {
        FieldElementLib.setGlobalPrime(CryptLib.secp256k1_p);
        var G = CryptLib.G;
        G.order = CryptLib.secp256k1_n;
        const z = 0x231c6f3d980a6b0fb7152f85cee7eb52bf92433d9919b9c5218cb08e79cce78;
        const e = 0x8b387de39861728c92ec9f589c303b1038ff60eb3963b12cd212263a1d1e0f00;
        std.debug.print("Signing the message...\n", .{});
        const sig = CryptLib.sign(z, e);
        std.debug.print("Verifying the signature...\n", .{});
        std.debug.print("valid: {}\n", .{CryptLib.verify(z, G.muli(e), sig)});
    }
}
