const std = @import("std");
const FieldElement = @import("finite-field.zig").FieldElement;

pub fn main() !void {
    std.debug.print("------------- FiniteFields -------------\n", .{});
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
}
