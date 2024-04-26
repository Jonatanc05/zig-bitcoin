const std = @import("std");
const FieldElementLib = @import("finite-field.zig");
const FieldElement = FieldElementLib.FieldElement;
const NumberType = FieldElementLib.NumberType;
const fe = FieldElementLib.fieldElementShortcut;
const CurvePoint = @import("elliptic-curve.zig").CurvePoint;

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
        std.debug.print("2 p3: {}\n", .{p3.mul(2)});
        std.debug.print("3 p3: {}\n", .{p3.mul(3)});
        std.debug.print("18 p3: {}\n", .{p3.mul(18)});
        std.debug.print("19 p3: {}\n", .{p3.mul(19)});
        std.debug.print("20 p3: {}\n", .{p3.mul(20)});
        std.debug.print("21 p3: {}\n", .{p3.mul(21)});
        std.debug.print("\n", .{});
    }
}
