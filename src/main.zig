const std = @import("std");
const ff = @import("finite-field.zig");

pub fn main() !void {
    const a = try ff.FieldElement.init(10, 13);
    const b = try ff.FieldElement.init(5, 13);
    std.debug.print("Element a: {}\n", .{a});
    std.debug.print("Element b: {}\n", .{b});
    std.debug.print("a + b: {}\n", .{try a.add(b)});
    std.debug.print("a - b: {}\n", .{try a.sub(b)});
    std.debug.print("b - a: {}\n", .{try b.sub(a)});
    std.debug.print("a * b: {}\n", .{try a.mul(b)});
    std.debug.print("a ** 2: {}\n", .{try a.pow(2)});
    std.debug.print("a / b: {}\n", .{try a.div(b)});
}
