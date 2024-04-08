const std = @import("std");
const FieldElement = @import("finite-field.zig").FieldElement;
const CurvePoint = @import("elliptic-curve.zig").CurvePoint;

pub fn main() !void {
    std.debug.print("\n------------- FiniteFields -------------\n", .{});
    {
        const a = FieldElement.init(10, 13);
        const b = FieldElement.init(5, 13);
        std.debug.print("Element a: {}\n", .{a});
        std.debug.print("Element b: {}\n", .{b});
        std.debug.print("a + b: {}\n", .{a.add(b)});
        std.debug.print("a - b: {}\n", .{a.sub(b)});
        std.debug.print("b - a: {}\n", .{b.sub(a)});
        std.debug.print("a * b: {}\n", .{a.mul(b)});
        std.debug.print("a ** 2: {}\n", .{a.pow(2)});
        std.debug.print("a / b: {}\n", .{a.div(b)});
        std.debug.print("\n", .{});
    }

    std.debug.print("------------- EllipticCurves -------------\n", .{});
    {
        const p1 = CurvePoint.init(2, 5, 5, 7);
        const p2 = CurvePoint.init(-1, -1, 5, 7);
        std.debug.print("Point p1: {}\n", .{p1});
        std.debug.print("Point p2: {}\n", .{p2});
        std.debug.print("p1 + p2: {}\n", .{p1.add(p2)});
        //std.debug.print("p1 - p2: {}\n", .{p1.sub(p2)});
        //std.debug.print("p2 - p1: {}\n", .{p2.sub(p1)});
        //std.debug.print("p1 * p2: {}\n", .{p1.mul(p2)});
        //std.debug.print("p1 ** 2: {}\n", .{p1.pow(2)});
        //std.debug.print("p1 / p2: {}\n", .{p1.div(p2)});
        //std.debug.print("\n", .{});
    }
}
