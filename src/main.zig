const std = @import("std");
const Report = @import("report.zig");

pub fn main() !void {
    const privkey: u256 = try std.fmt.parseInt(u256, @embedFile(".privkey")[0..64], 16);

    try Report.print(privkey);
}
