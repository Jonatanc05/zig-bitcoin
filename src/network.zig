const std = @import("std");
const net = std.net;
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

// managed dependencies
const Cursor = @import("cursor.zig").Cursor;
const Bitcoin = @import("bitcoin.zig");

const genesis_block_hash: u256 = 0xdeadbeef;

fn ipv4_as_ipv6(ipv4: [4]u8) [16]u8 {
    return [1]u8{0} ** 10 ++ [2]u8{ 0xff, 0xff } ++ ipv4;
}

pub const Protocol = struct {
    pub const current_version = 70014;

    const magic_mainnet = 0xf9beb4d9;
    const magic_testnet = 0x0b110907;

    /// Union for any message accepted by the Bitcoin protocol and its corresponding payload as data
    pub const Message = union(enum) {
        ping: struct {
            nonce: u64,

            pub fn serialize(self: @This(), writer: std.io.AnyWriter) anyerror!void {
                // length
                try expect(@sizeOf(@TypeOf(self)) == 8);
                try writer.writeInt(u32, 8, .little);

                // checksum
                var hash: [32]u8 = undefined;
                var nonce_bytes: [8]u8 = undefined;
                std.mem.writeInt(u64, &nonce_bytes, self.nonce, .little);
                Sha256.hash(&nonce_bytes, &hash, .{});
                Sha256.hash(&hash, &hash, .{});
                try writer.writeAll(hash[0..4]);

                // payload
                try writer.writeInt(u64, self.nonce, .little);
            }

            pub fn parse(data: []const u8, unused: std.mem.Allocator) anyerror!ParseResult {
                _ = unused;
                var reader = Cursor.init(data);

                var res = ParseResult{
                    .value = Message{ .ping = .{ .nonce = undefined } },
                    .bytes_read_count = 0,
                };

                const length = reader.readInt(u32, .little);
                res.bytes_read_count += 4;
                assert(length == 8);

                var chcksum: [4]u8 = undefined;
                reader.readBytes(&chcksum);
                res.bytes_read_count += 4;

                const nonce = reader.readInt(u64, .little);
                res.value.ping.nonce = nonce;
                res.bytes_read_count += 8;

                var hash: [32]u8 = undefined;
                var nonce_bytes: [8]u8 = undefined;
                std.mem.writeInt(u64, &nonce_bytes, nonce, .little);
                Sha256.hash(&nonce_bytes, &hash, .{});
                Sha256.hash(&hash, &hash, .{});
                const expected_checksum: [4]u8 = hash[0..4].*;
                if (!std.mem.eql(u8, &chcksum, &expected_checksum)) {
                    return error.ChecksumMismatch;
                }

                return res;
            }
        },
        pong: struct {
            nonce: u64,

            pub fn serialize(self: @This(), writer: std.io.AnyWriter) anyerror!void {
                // length
                try expect(@sizeOf(@TypeOf(self)) == 8);
                try writer.writeInt(u32, 8, .little);

                // checksum
                var hash: [32]u8 = undefined;
                var nonce_bytes: [8]u8 = undefined;
                std.mem.writeInt(u64, &nonce_bytes, self.nonce, .little);
                Sha256.hash(&nonce_bytes, &hash, .{});
                Sha256.hash(&hash, &hash, .{});
                try writer.writeAll(hash[0..4]);

                // payload
                try writer.writeInt(u64, self.nonce, .little);
            }

            pub fn parse(data: []const u8, unused: std.mem.Allocator) anyerror!ParseResult {
                _ = unused;
                var reader = Cursor.init(data);
                var res = ParseResult{
                    .value = Message{ .pong = .{ .nonce = undefined } },
                    .bytes_read_count = 0,
                };

                const length = reader.readInt(u32, .little);
                res.bytes_read_count += 4;
                assert(length == 8);

                var chcksum: [4]u8 = undefined;
                reader.readBytes(&chcksum);
                res.bytes_read_count += 4;

                const nonce = reader.readInt(u64, .little);
                res.value.pong.nonce = nonce;
                res.bytes_read_count += 8;

                var hash: [32]u8 = undefined;
                var nonce_bytes: [8]u8 = undefined;
                std.mem.writeInt(u64, &nonce_bytes, nonce, .little);
                Sha256.hash(&nonce_bytes, &hash, .{});
                Sha256.hash(&hash, &hash, .{});
                const expected_checksum: [4]u8 = hash[0..4].*;
                if (!std.mem.eql(u8, &chcksum, &expected_checksum)) {
                    return error.ChecksumMismatch;
                }

                return res;
            }
        },
        version: struct {
            version: i32 = current_version,
            // @TODO make it BIP159 compliant (https://github.com/bitcoin/bips/blob/master/bip-0159.mediawiki)
            services: u64 = 0,
            timestamp: i64,
            receiver_services: u64 = 0,
            receiver_ip: [16]u8 = [1]u8{0} ** 16,
            receiver_port: u16 = 8333,
            sender_services: u64 = 0,
            sender_ip: [16]u8 = ipv4_as_ipv6([4]u8{ 127, 0, 0, 1 }),
            sender_port: u16 = 8333,
            nonce: u64 = 0x1f297b45,
            user_agent: []const u8,
            start_height: i32 = 0,
            relay: bool = false,

            pub fn serialize(self: @This(), writer: std.io.AnyWriter) anyerror!void {
                var payload_buffer: [256]u8 = undefined;
                {
                    var bufstream = std.io.fixedBufferStream(&payload_buffer);
                    const bufwriter = bufstream.writer();
                    try bufwriter.writeInt(i32, self.version, .little);
                    try bufwriter.writeInt(u64, self.services, .little);
                    try bufwriter.writeInt(i64, self.timestamp, .little);

                    try bufwriter.writeInt(u64, self.receiver_services, .little);
                    try bufwriter.writeAll(&self.receiver_ip);
                    try bufwriter.writeInt(u16, self.receiver_port, .big);

                    try bufwriter.writeInt(u64, self.sender_services, .little);
                    try bufwriter.writeAll(&self.sender_ip);
                    try bufwriter.writeInt(u16, self.sender_port, .big);

                    try bufwriter.writeInt(u64, self.nonce, .little);
                    std.debug.assert(self.user_agent.len < 0xfd); // It's supposed to be read as varint
                    try bufwriter.writeInt(u8, @intCast(self.user_agent.len), .little);
                    try bufwriter.writeAll(self.user_agent);
                    try bufwriter.writeInt(i32, self.start_height, .little);

                    try bufwriter.writeInt(u8, if (self.relay) 1 else 0, .big);
                }

                // length
                const payload_size = 86 + self.user_agent.len;
                try writer.writeInt(u32, @intCast(payload_size), .little);

                // checksum
                var hash: [32]u8 = undefined;
                Sha256.hash(payload_buffer[0..payload_size], &hash, .{});
                Sha256.hash(&hash, &hash, .{});
                try writer.writeAll(hash[0..4]);

                // payload
                try writer.writeAll(payload_buffer[0..payload_size]);
            }

            pub fn parse(data: []const u8, alloc: std.mem.Allocator) anyerror!ParseResult {
                var reader = Cursor.init(data);
                var res = ParseResult{
                    .value = Message{ .version = .{ .timestamp = 0, .user_agent = undefined } },
                    .bytes_read_count = 0,
                };

                const length = reader.readInt(u32, .little);
                _ = length;
                res.bytes_read_count += 4;

                var chcksum: [4]u8 = undefined;
                reader.readBytes(&chcksum);
                res.bytes_read_count += 4;

                var out = &res.value.version;

                out.version = reader.readInt(i32, .little);
                res.bytes_read_count += 4;
                out.services = reader.readInt(u64, .little);
                out.timestamp = reader.readInt(i64, .little);
                res.bytes_read_count += 8 * 2;

                out.receiver_services = reader.readInt(u64, .little);
                res.bytes_read_count += 8;

                reader.readBytes(&out.receiver_ip);
                res.bytes_read_count += out.receiver_ip.len;

                out.receiver_port = reader.readInt(u16, .little);
                res.bytes_read_count += 2;

                out.sender_services = reader.readInt(u64, .little);
                res.bytes_read_count += 8;

                reader.readBytes(&out.sender_ip);
                res.bytes_read_count += out.sender_ip.len;
                out.sender_port = reader.readInt(u16, .little);
                res.bytes_read_count += 2;

                out.nonce = reader.readInt(u64, .little);
                res.bytes_read_count += 8;

                const user_agent_len = reader.readInt(u8, .little);
                res.bytes_read_count += 1;

                var buffer: [256]u8 = undefined;
                reader.readBytes(buffer[0..user_agent_len]);
                out.user_agent = try alloc.dupe(u8, buffer[0..user_agent_len]);
                res.bytes_read_count += user_agent_len;

                out.start_height = reader.readInt(i32, .little);
                res.bytes_read_count += 4;
                out.relay = (reader.readInt(u8, .little)) > 0;
                res.bytes_read_count += 1;

                // TODO checksum validation
                //var hash: [32]u8 = undefined;
                //const bytes_ptr = @as([*]u8, @ptrCast(@alignCast(std.mem.asBytes(&out))));

                //Sha256.hash(bytes_ptr[0..@sizeOf(@TypeOf(out.*))], &hash, .{});
                //Sha256.hash(&hash, &hash, .{});
                //const expected_checksum: [4]u8 = hash[0..4].*;
                //if (!std.mem.eql(u8, &chcksum, &expected_checksum)) {
                //    return error.ChecksumMismatch;
                //}

                return res;
            }

            pub fn deinit(self: @This(), alloc: std.mem.Allocator) void {
                alloc.free(self.user_agent);
            }
        },
        verack: struct {
            pub fn serialize(self: @This(), writer: std.io.AnyWriter) anyerror!void {
                _ = self;
                const serialized = [_]u8{ 0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x61, 0x63, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2 };
                try writer.writeAll(&serialized);
            }

            pub fn parse(data: []const u8, unused: std.mem.Allocator) anyerror!ParseResult {
                _ = unused;
                var reader = Cursor.init(data);
                assert(reader.readInt(u32, .little) == 0);
                assert(reader.readInt(u32, .big) == 0x5df6e0e2);
                return .{ .value = .{ .verack = .{} }, .bytes_read_count = 8 };
            }
        },
        getheaders: struct {
            version: i32 = 70014,
            hash_count: u32 = 1,
            hash_start_block: u256 = genesis_block_hash,
            hash_final_block: u256 = 0,

            pub fn serialize(self: @This(), writer: std.io.AnyWriter) anyerror!void {
                try writer.writeInt(i32, self.version, .little);
                try Bitcoin.Aux.writeVarint(writer, self.hash_count);
                try writer.writeInt(u256, self.hash_start_block, .little);
                try writer.writeInt(u256, self.hash_final_block, .little);
            }

            pub fn parse(data: []const u8, unused: std.mem.Allocator) anyerror!ParseResult {
                _ = unused;
                var cursor = Cursor.init(data);
                var res = ParseResult{
                    .value = .{ .getheaders = .{} },
                    .bytes_read_count = 0,
                };

                res.value.getheaders.version = cursor.readInt(i32, .little);
                res.bytes_read_count += 4;

                const starting_index = cursor.index;
                res.value.getheaders.hash_count = cursor.readVarint();
                res.bytes_read_count += @intCast(cursor.index - starting_index);

                res.value.getheaders.hash_start_block = cursor.readInt(u256, .little);
                res.bytes_read_count += 32;

                res.value.getheaders.hash_final_block = cursor.readInt(u256, .little);
                res.bytes_read_count += 32;

                return res;
            }
        },
        headers: struct {
            data: Bitcoin.Block,
            count: u32,

            pub fn serialize(self: @This(), writer: std.io.AnyWriter) anyerror!void {
                var buffer: [80]u8 = undefined;
                const serialization = try self.data.serialize(&buffer);
                try writer.writeAll(serialization);
                try Bitcoin.Aux.writeVarint(writer, self.count);
            }

            pub fn parse(data: []const u8, unused: std.mem.Allocator) anyerror!ParseResult {
                _ = unused;
                const block_res = try Bitcoin.Block.parse(data);
                assert(@sizeOf(Bitcoin.Block) == 80);
                var cursor = Cursor.init(data[80..]);
                const starting_index = cursor.index;
                const count = cursor.readVarint();
                const total_read: u32 = 80 + @as(u32, @intCast(cursor.index - starting_index));
                return .{
                    .value = .{ .headers = .{ .data = block_res, .count = count } },
                    .bytes_read_count = total_read,
                };
            }
        },

        // Enforce function signatures on each union tag (each protocol command)
        comptime {
            const T = Protocol.Message;

            const Function = struct {
                mandatory: bool,
                name: []const u8,
                return_type: type,
                params: []const type,
            };
            const functions = .{
                Function{ .mandatory = true, .name = "serialize", .return_type = anyerror!void, .params = &[_]type{ void, std.io.AnyWriter } },
                Function{ .mandatory = true, .name = "parse", .return_type = anyerror!Protocol.Message.ParseResult, .params = &[_]type{ []const u8, std.mem.Allocator } },
                Function{ .mandatory = false, .name = "deinit", .return_type = void, .params = &[_]type{std.mem.Allocator} },
            };

            for (@typeInfo(T).@"union".fields) |field| {
                for (functions) |function| {
                    if (!@hasDecl(field.type, function.name)) {
                        if (function.mandatory) {
                            var buf: [200]u8 = undefined;
                            @compileError(std.fmt.bufPrint(&buf, "A {} function is required for {}.{}", .{ function.name, @typeName(T), field.name }) catch "E879234");
                        } else continue;
                    }
                    const pf = @field(field.type, function.name);
                    const fn_info = @typeInfo(@TypeOf(pf)).@"fn";
                    if (fn_info.return_type != function.return_type) {
                        var buf: [200]u8 = undefined;
                        @compileError(std.fmt.bufPrint(&buf, "The function {s}.{s}.{s} has the wrong signature. Should be: fn {s}({d}) {s}", .{ @typeName(T), field.name, function.name, function.name, function.params.len, @typeName(function.return_type) }) catch "E1293485");
                    }

                    // TODO check parameters and ignore when void
                }
            }
        }

        /// Includes the protocol headers (https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure)
        pub fn serialize(self: *const Message, buffer: []u8) ![]u8 {
            var stream = std.io.fixedBufferStream(buffer);
            const writer = stream.writer();

            // magic
            try writer.writeInt(u32, Protocol.magic_mainnet, .big);

            // command
            try writer.writeAll(&command_bytes: {
                const command = @tagName(self.*);
                var command_bytes = [_]u8{0} ** 12;
                std.mem.copyForwards(u8, command_bytes[0..], command);
                break :command_bytes command_bytes;
            });

            // payload length, checksum and contents
            switch (self.*) {
                inline else => |field| try field.serialize(writer.any()),
            }
            return buffer[0..writer.context.pos];
        }

        const ParseResult = struct { value: Message, bytes_read_count: u32 };

        pub fn parse(bytes: []u8, alloc: std.mem.Allocator) !ParseResult {
            var strm = std.io.fixedBufferStream(bytes);
            var reader = strm.reader();
            var res: ParseResult = .{
                .value = undefined,
                .bytes_read_count = 0,
            };

            const magic = try reader.readInt(u32, .big);
            res.bytes_read_count += 4;
            if (magic != magic_mainnet and magic != magic_testnet) // might try to assert the magic read and the current context in the future
                return error.MagicNumberExpected;

            var command: [12]u8 = [_]u8{0} ** 12;
            assert(try reader.readAll(&command) == 12);
            res.bytes_read_count += 12;

            // setup a map of functions by name
            assert(res.bytes_read_count == 16);
            const first_zero_index: usize = for (command, 0..) |c, i| {
                if (c == 0) break i;
            } else 12;
            const tagName = command[0..first_zero_index];
            inline for (@typeInfo(Message).@"union".fields) |field| {
                if (std.mem.eql(u8, field.name, tagName)) {
                    const version_res = try field.type.parse(bytes[res.bytes_read_count..], alloc);
                    res.value = version_res.value;
                    res.bytes_read_count += version_res.bytes_read_count;
                }
            }

            return res;
        }

        pub fn deinit(self: Message, alloc: std.mem.Allocator) void {
            inline for (@typeInfo(Message).@"union".fields) |field| {
                switch (self) {
                    inline else => |field_instance| {
                        if (@hasDecl(field.type, "deinit")) {
                            if (@TypeOf(field_instance) == field.type)
                                field_instance.deinit(alloc);
                        }
                    },
                }
            }
        }
    };

    pub fn checksum(bytes: []u8) [4]u8 {
        var hash: [32]u8 = undefined;
        Sha256.hash(bytes, &hash, .{});
        Sha256.hash(&hash, &hash, .{});
        return hash[0..4];
    }
};

pub const Node = struct {
    pub const Connection = struct {
        peer_address: net.Address,
        peer_version: i32,
        stream: net.Stream,
        handshaked: bool,
        user_agent: [30]u8,
    };

    pub fn connect(address: net.Address, alloc: std.mem.Allocator) !Connection {
        const stream = net.tcpConnectToAddress(address) catch |err| {
            std.debug.print("Failed to connect to {}: {s}\n", .{ address, @errorName(err) });
            return error.ConnectionError;
        };
        var connection = Connection{
            .peer_address = address,
            .peer_version = 0,
            .stream = stream,
            .handshaked = false,
            .user_agent = undefined,
        };

        // Start handshake
        const timestamp = std.time.timestamp();
        try Node.sendMessage(connection, .{
            .version = .{
                .timestamp = timestamp,
                .nonce = @intCast(timestamp),
                .start_height = 0,
                .user_agent = "Zignode",
            },
        });

        // Read answer
        var received: [2]Protocol.Message = undefined;

        received[0] = try Node.readMessage(connection, alloc);
        defer received[0].deinit(alloc);

        received[1] = try Node.readMessage(connection, alloc);
        defer received[1].deinit(alloc);

        // Information to obtain
        var verack_received: bool = false;
        var version_received: ?i32 = null;
        var user_agent_received: [30]u8 = [1]u8{'.'} ++ [1]u8{' '} ** 29;
        for (received) |msg| {
            switch (msg) {
                Protocol.Message.version => |v_msg| {
                    if (v_msg.version < Protocol.current_version)
                        return error.VersionMismatch;
                    for (v_msg.user_agent, 0..) |ch, i| {
                        if (i > user_agent_received.len) break;
                        user_agent_received[i] = ch;
                    }
                    version_received = v_msg.version;
                },
                Protocol.Message.verack => verack_received = true,
                else => return error.UnexpectedMessageOnHandshake,
            }
        }

        if (version_received != null and verack_received) {
            try Node.sendMessage(connection, Protocol.Message{ .verack = .{} });
            connection.peer_version = version_received.?;
            connection.handshaked = true;
            connection.user_agent = user_agent_received;
            return connection;
        }

        return error.HandshakeFailed;
    }

    pub fn sendMessage(connection: Node.Connection, message: Protocol.Message) !void {
        var buffer: [1024]u8 = undefined;
        const data = try message.serialize(&buffer);
        connection.stream.writeAll(data) catch |err| {
            std.debug.print("Failed to write to socket at {any}: {s}\n", .{ connection.peer_address, @errorName(err) });
            return error.SendError;
        };
    }

    /// Synchronously waits to receive bytes. Caller should call .deinit() returned value
    pub fn readMessage(connection: Connection, alloc: std.mem.Allocator) !Protocol.Message {
        const header_len = 24;
        var buffer = ([1]u8{0} ** header_len) ++ ([1]u8{0} ** (1024 * 256));
        var header_slice = buffer[0..header_len];

        const read_count1 = connection.stream.readAtLeast(header_slice, header_len) catch |err| {
            std.debug.print("Failed to read from socket at {any}: {s}\n", .{ connection.peer_address, @errorName(err) });
            return error.ReceiveError;
        };
        if (read_count1 < header_len) return error.ReceiveError;
        const payload_length = std.mem.readInt(u32, header_slice[16..][0..4], .little);

        const read_count2 = connection.stream.readAtLeast(buffer[header_len..][0..payload_length], payload_length) catch |err| {
            std.debug.print("Failed to read from socket at {any}: {s}\n", .{ connection.peer_address, @errorName(err) });
            return error.ReceiveError;
        };
        if (read_count2 < payload_length) return error.ReceiveError;

        const result = Protocol.Message.parse(buffer[0..], alloc) catch return error.PayloadParseError;
        return result.value;
    }
};

//#region TESTS #########################################################################

const expect = std.testing.expect;
const t_alloc = std.testing.allocator;

test "protocol: message serialization" {
    const message = Protocol.Message{ .ping = .{ .nonce = 0x127f } };
    var buffer = [_]u8{0} ** 32;
    const res = try message.serialize(&buffer);
    try expect(res.len == 32);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xF9, 0xBE, 0xB4, 0xD9, 0x70, 0x69, 0x6E, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x4E, 0x6E, 0xDE, 0x71, 0x7f, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        res,
    );

    const parsed_res = (try Protocol.Message.parse(res, t_alloc)).value;
    var buffer2 = [_]u8{0} ** 32;
    const serialized_parsed_res = try parsed_res.serialize(&buffer2);

    try std.testing.expectEqualSlices(
        u8,
        res,
        serialized_parsed_res,
    );
}

test "protocol: handshake and version" {
    //const host = "58.96.123.120"; // from bitcoin core's nodes_main.txt
    const host = "74.220.255.190"; // from bitcoin core's nodes_main.txt
    //const host = "77.173.132.140"; // from bitcoin core's nodes_main.txt
    const port = 8333;
    const address = try net.Address.resolveIp(host, port);
    const connection = try Node.connect(address, t_alloc);
    try expect(connection.handshaked);
    try expect(connection.peer_version > 0);
}

//#endregion
