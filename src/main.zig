const std = @import("std");
const Bitcoin = @import("bitcoin.zig");
const Network = @import("network.zig");
const GenericWriter = std.io.GenericWriter;
const GenericReader = std.io.GenericReader;
const builtin = @import("builtin");

// TODO
// - Request all block headers
// - SPV

const MAX_CONNECTIONS = 9;

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
        } else {
            break :blk .{ std.heap.smp_allocator, null };
        }
    };
    defer if (debug != null) {
        if (debug.?.deinit() == .leak) {
            @breakpoint(); // not sure what to do
            std.debug.print("Memory leak detected!\n", .{});
        }
    };

    const ConnectionSlot = struct {
        alive: bool,
        data: Network.Node.Connection,
    };
    const state: struct {
        connections: []ConnectionSlot,
    } = .{
        .connections = try allocator.alloc(ConnectionSlot, MAX_CONNECTIONS),
    };

    while (true) {
        try stdout.print("\n################################################\n", .{});
        try stdout.print("\nHello dear hodler, tell me what can I do for you\n", .{});
        try stdout.print("1. List connections (interact with peers)\n", .{});
        try stdout.print("2. Connect to a new peer\n", .{});
        try stdout.print("3. Sign a transaction\n", .{});
        try stdout.print("4. Exit\n\n", .{});

        var buf: [9]u8 = undefined;
        const input = try stdin.readUntilDelimiter(&buf, '\n');
        const b = input[0];
        outerswitch: switch (b) {
            '1' => {
                const anyConnection = for (state.connections) |conn| {
                    if (conn.alive) break true;
                } else false;
                if (!anyConnection) {
                    try stdout.print("\n<empty>\n", .{});
                } else {
                    try stdout.print("\nPeer list:\n", .{});
                    for (state.connections, 0..) |conn, i| {
                        if (conn.alive)
                            try stdout.print("{d}: {any} | {s}\n", .{ i + 1, conn.data.peer_address, conn.data.user_agent });
                    }
                    try stdout.print("\nType 'i' followed by a number to interact with a peer (ex.: 'i 2')\n", .{});
                }
            },
            '2' => {
                const new_peer_id = for (state.connections, 0..) |conn, i| {
                    if (!conn.alive) break i;
                } else {
                    try stdout.print("\nERROR: reached maximum number of peers\n", .{});
                    break;
                };

                //const targetIpAddress = std.net.Address{ .in = .init([_]u8{74,220,255,190},8333) };//try promptIpAddress();
                //const targetIpAddress = std.net.Address{ .in = .init([_]u8{58,96,123,120},8333) };//try promptIpAddress();
                const targetIpAddress = try promptIpAddress();

                state.connections[new_peer_id].data = try Network.Node.connect(targetIpAddress, allocator);
                state.connections[new_peer_id].alive = true;
                try stdout.print("\nConnection established successfully with \nPeer ID: {d}\nIP: {any}\nUser Agent: {s}\n\n", .{
                    new_peer_id + 1,
                    state.connections[new_peer_id].data.peer_address,
                    state.connections[new_peer_id].data.user_agent,
                });
            },
            'i' => {
                std.debug.assert(MAX_CONNECTIONS < 10); // Based on this premise we assume 3 character input: 'i', ' ' and 'X' as single-digit number
                const trimmed = std.mem.trimRight(u8, input, &.{' ', '\r', '\n'});
                if (trimmed.len != 3 or trimmed[1] != ' ' or trimmed[2] < '1' or trimmed[2] > '9') {
                    try stdout.print("Not sure what you mean... try like 'i 1'\n", .{});
                    std.log.debug("'{s}'\n", .{trimmed});
                    break :outerswitch;
                }

                const peer_id = (try std.fmt.charToDigit(trimmed[2], 10)) - 1;
                if (!state.connections[peer_id].alive)
                    try stdout.print("That's not a valid peer id\n", .{});

                const connection = state.connections[peer_id].data;
                try stdout.print("\nWhat do you want to do?\n", .{});
                try stdout.print("1. disconnect from peer\n", .{});
                try stdout.print("2. ask for block headers\n", .{});
                const action = try stdin.readUntilDelimiter(&buf, '\n');
                switch (action[0]) {
                    '1' => {
                        state.connections[peer_id].alive = false;
                    },
                    '2' => {
                        try stdout.print("Requesting for block headers...\n", .{});
                        try Network.Node.sendMessage(connection, Network.Protocol.Message{
                            .getheaders = .{
                                .hash_count = 1,
                                .hash_start_block = Network.genesis_block_hash,
                                //.hash_final_block = 0x00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048, // genesis successor
                                //.hash_final_block = 0x000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd, // genesis successor's successor
                                .hash_final_block = 0,
                            },
                        });

                        var message: Network.Protocol.Message = undefined;
                        defer message.deinit(allocator);
                        outer: while (true) {
                            if (Network.Node.readMessage(connection, allocator)) |msg| {
                                switch (msg) {
                                    Network.Protocol.Message.ping => |ping| {
                                        try Network.Node.sendMessage(
                                            connection,
                                            Network.Protocol.Message{ .pong = .{ .nonce = ping.nonce } },
                                        );
                                    },
                                    Network.Protocol.Message.headers => {
                                        message = msg;
                                        break :outer;
                                    },

                                    // @TODO have experienced being answered with inv

                                    else => {
                                        std.debug.print("Unexpected command: {s}\n", .{@tagName(msg)});
                                    },
                                }
                                msg.deinit(allocator);
                            } else |err| switch (err) {
                                error.UnsupportedCommandReceived => continue,
                                else => return err,
                            }
                        }
                        std.debug.assert(message == .headers);
                        const blocks = message.headers.data;
                        try stdout.print("Blocks received ({d}):\n", .{blocks.len});
                        var prev_hash: [32]u8 = undefined;
                        std.mem.writeInt(u256, &prev_hash, Network.genesis_block_hash, .big);
                        for (blocks, 0..) |block, i| {
                            var hash: [32]u8 = undefined;
                            block.hash(&hash);
                            try stdout.print("[{d}] {s}: PoW {s}, prev {s}\n", .{
                                i,
                                std.fmt.fmtSliceHexLower(hash[0..10]),
                                if (block.checkProofOfWork()) "OK" else "XX",
                                if (std.mem.eql(u8, &block.prev_block, &prev_hash)) "OK" else "XX",
                            });
                            prev_hash = hash;
                        }
                    },
                    else => continue,
                }
            },
            '3' => {
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
