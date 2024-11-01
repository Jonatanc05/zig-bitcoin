const std = @import("std");
const Bitcoin = @import("bitcoin.zig");
const GenericWriter = std.io.GenericWriter;
const GenericReader = std.io.GenericReader;

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();
    const privkey: u256 = try std.fmt.parseInt(u256, @embedFile(".privkey")[0..64], 16);
    var address: [40]u8 = undefined;
    const s = Bitcoin.Address.fromPrivkey(privkey, true, &address);
    try stdout.print("\nYour address is {s}\n", .{address[s..]});

    while (true) {
        try stdout.print("\n################################################\n\nHello dear hodler, tell me what can I do for you\n1. Show me what you got\n2. Sign a transaction\n3. Exit\n\n", .{});

        var buf: [9]u8 = undefined;
        const input = try stdin.readUntilDelimiter(&buf, '\n');
        const b = input[0];
        switch (b) {
            '1' => try @import("report.zig").print(privkey),
            '2' => {
                var tx = try promptTransaction();
                defer tx.deinit();
                const input_index = 0;
                var prompt_buf: [256]u8 = undefined;
                const prev_pubkey = try promptBytesHex(&prompt_buf, "Previous pubkey");
                try tx.sign(privkey, input_index, prev_pubkey);
                const bytes = try tx.serialize(std.heap.page_allocator);
                defer std.heap.page_allocator.free(bytes);
                try stdout.print("\nTransaction:\n{}\n", .{std.fmt.fmtSliceHexLower(bytes)});
            },
            '3' => break,
            else => {
                try stdout.print("\ninvalid byte read: {x}\n", .{b});
            },
        }
    }
}

fn promptTransaction() !Bitcoin.Tx {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("NOTE: Only P2PKH is currently supported\n", .{});
    const testnet = try promptBool("Do you want to use testnet?");
    var buf: [256]u8 = undefined;
    var buf2: [256]u8 = undefined;
    const prev_txid_bytes = try promptBytesHex(&buf, "Previous TXID (32 bytes)");
    const prev_txid = try std.fmt.parseInt(u256, prev_txid_bytes[0..64], 16);
    const prev_output_index = try promptInt(u32, "Previous output index");
    const amount = try promptInt(u64, "Amount to send");
    const target_address = try promptString(&buf2, "Target address");
    return try Bitcoin.Tx.initP2PKH(testnet, prev_txid, prev_output_index, amount, target_address);
}

fn promptBool(msg: []const u8) !bool {
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();
    try stdout.print("{s} [y/n]: ", .{msg});
    var buf: [9]u8 = undefined;
    const input = try stdin.readUntilDelimiter(&buf, '\n');
    switch (input[0]) {
        'y' => return true,
        'n' => return false,
        else => return error.InvalidInput,
    }
}

fn promptBytesHex(buffer: []u8, msg: []const u8) ![]u8 {
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();
    try stdout.print("{s} [hex]: ", .{msg});
    var answer = try stdin.readUntilDelimiter(buffer, '\n');
    if (answer[answer.len - 1] == '\r') answer = answer[0 .. answer.len - 1];
    return answer;
}

fn promptString(buffer: []u8, msg: []const u8) ![]u8 {
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();
    try stdout.print("{s}: ", .{msg});
    var answer = try stdin.readUntilDelimiter(buffer, '\n');
    if (answer[answer.len - 1] == '\r') answer = answer[0 .. answer.len - 1];
    return answer;
}

fn promptInt(comptime T: type, msg: []const u8) !T {
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();
    try stdout.print("{s} [numeric]: ", .{msg});
    var buf: [256]u8 = undefined;
    var answer = while (true) {
        const input = try stdin.readUntilDelimiter(&buf, '\n');
        if (input.len > 0 and input[0] != '\n' and input[0] != '\r')
            break input;
    };
    if (answer[answer.len - 1] == '\r') answer = answer[0 .. answer.len - 1];
    return try std.fmt.parseInt(T, answer[0..], 10);
}
