const std = @import("std");
const Bitcoin = @import("bitcoin.zig");
const Network = @import("network.zig");
const GenericWriter = std.io.GenericWriter;
const GenericReader = std.io.GenericReader;
const builtin = @import("builtin");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();
    const privkey: u256 = try std.fmt.parseInt(u256, @embedFile(".privkey")[0..64], 16);
    var addr_buf: [40]u8 = undefined;
    const address = Bitcoin.Address.fromPrivkey(privkey, true, &addr_buf);
    try stdout.print("\nYour address is {s}\n", .{address});

    const allocator, var debug: ?std.heap.DebugAllocator(.{}) = blk: {
        if (builtin.mode == .Debug) {
            var gpa = std.heap.DebugAllocator(.{}).init;
            break :blk .{ gpa.allocator(), gpa };
        }
        break :blk .{ std.heap.smp_allocator, null };
    };

    defer if (debug != null) {
        if (debug.?.deinit() == .leak) {
            @breakpoint(); // not sure what to do
            std.debug.print("Memory leak detected!\n", .{});
        }
    };

    while (true) {
        try stdout.print("\n################################################\n\nHello dear hodler, tell me what can I do for you\n1. Show me what you got\n2. Sign a transaction\n3. Connect to another node\n4. Exit\n\n", .{});

        var buf: [9]u8 = undefined;
        const input = try stdin.readUntilDelimiter(&buf, '\n');
        const b = input[0];
        switch (b) {
            '1' => try @import("report.zig").print(privkey),
            '2' => {
                var tx = try promptTransaction(allocator);
                defer tx.deinit(allocator);
                const input_index = 0;
                var prompt_buf: [256]u8 = undefined;
                const prev_pubkey = try promptBytesHex(&prompt_buf, "Previous pubkey");
                try tx.sign(privkey, input_index, prev_pubkey, allocator);
                const bytes = try tx.serialize(allocator);
                defer allocator.free(bytes);
                try stdout.print("\nTransaction:\n{}\n", .{std.fmt.fmtSliceHexLower(bytes)});
            },
            '3' => {
                //const targetIpAddress = std.net.Address{ .in = .init([_]u8{74,220,255,190},8333) };//try promptIpAddress();
                //const targetIpAddress = std.net.Address{ .in = .init([_]u8{58,96,123,120},8333) };//try promptIpAddress();
                const targetIpAddress = try promptIpAddress();
                const connection = try Network.Node.connect(targetIpAddress, allocator);
                try stdout.print("\nConnection established successfully with \nIP: {any}\nUser Agent: {s}\n\n", .{ connection.peer_address, connection.user_agent });

                try stdout.print("What do you want to do?\n1. ask for genesis block headers\n\n", .{});
                const action = try stdin.readUntilDelimiter(&buf, '\n');
                switch (action[0]) {
                    '1' => {
                        try stdout.print("Requesting for block headers...\n", .{});
                        try Network.Node.sendMessage(connection, Network.Protocol.Message{ .getheaders = .{
                            .hash_start_block = Network.genesis_block_hash,
                            .hash_final_block = 0x00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048,
                        } });
                        const msg = try Network.Node.readMessage(connection, allocator);
                        defer msg.deinit(allocator);
                        try stdout.print("Response:\n{any}\n", .{msg});
                    },
                    else => continue,
                }
            },
            '4' => break,
            else => {
                try stdout.print("\ninvalid byte read: {x}\n", .{b});
            },
        }
    }
}

fn promptTransaction(alloc: std.mem.Allocator) !Bitcoin.Tx {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("NOTE: Only P2PKH is currently supported\n", .{});
    const testnet = try promptBool("Do you want to use testnet?");
    var buf: [256]u8 = undefined;
    var buf2: [256]u8 = undefined;
    const prev_txid_bytes = try promptBytesHex(&buf, "Previous TXID (32 bytes)");
    const prev_txid = try std.fmt.parseInt(u256, prev_txid_bytes[0..64], 16);
    const prev_output_index = try promptInt(u32, "Previous output index", .{});
    const amount = try promptInt(u64, "Amount to send", .{});
    const target_address = try promptString(&buf2, "Target address");
    return try Bitcoin.Tx.initP2PKH(.{
        .testnet = testnet,
        .prev_txid = prev_txid,
        .prev_output_index = prev_output_index,
        .amount = amount,
        .target_address = target_address,
        .alloc = alloc,
    });
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

const PromptIntOpts = struct { default_value: ?comptime_int = null };
fn promptInt(comptime T: type, msg: []const u8, opts: PromptIntOpts) !T {
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();
    if (opts.default_value) |default| {
        try stdout.print("{s} [numeric, default={}]: ", .{ msg, default });
    } else {
        try stdout.print("{s} [numeric]: ", .{msg});
    }
    var buf: [256]u8 = undefined;
    var answer: []u8 = while (true) {
        const input = try stdin.readUntilDelimiter(&buf, '\n');
        if (input.len > 0 and input[0] != '\n' and input[0] != '\r') {
            break input;
        } else if (opts.default_value != null) {
            break &[0]u8{};
        }
    };
    if (answer.len == 0) return opts.default_value orelse unreachable;
    if (answer[answer.len - 1] == '\r') answer = answer[0 .. answer.len - 1];
    return try std.fmt.parseInt(T, answer[0..], 10);
}

fn promptIpAddress() !std.net.Address {
    var buf: [256]u8 = undefined;
    const ip = try promptString(&buf, "Enter the IPv4 or IPv6 [without port]");
    const port = try promptInt(u16, "Enter the port", .{ .default_value = 8333 });
    return try std.net.Address.resolveIp(ip, port);
}
