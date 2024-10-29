const std = @import("std");

pub fn main() !void {
    const privkey: u256 = try std.fmt.parseInt(u256, @embedFile(".privkey")[0..64], 16);
    try @import("report.zig").print(privkey);
}
