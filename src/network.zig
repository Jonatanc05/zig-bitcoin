const std = @import("std");
const net = std.net;
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

// managed dependencies
const Cursor = @import("cursor.zig").Cursor;
const Bitcoin = @import("bitcoin.zig");

pub const genesis_block_hash: u256 = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f;

fn ipv4_as_ipv6(ipv4: [4]u8) [16]u8 {
    return [1]u8{0} ** 10 ++ [2]u8{ 0xff, 0xff } ++ ipv4;
}

pub const Protocol = struct {
    pub const current_version = 70014;

    const magic_mainnet = 0xf9beb4d9;
    const magic_testnet = 0x0b110907;
    const header_len = 24;

    /// Union for any message accepted by the Bitcoin protocol and its corresponding payload as data
    pub const Message = union(enum) {
        ping: struct {
            nonce: u64,

            pub fn serialize(self: @This(), writer: std.io.AnyWriter) anyerror!void {
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
                try writer.writeInt(i32, self.version, .little);
                try writer.writeInt(u64, self.services, .little);
                try writer.writeInt(i64, self.timestamp, .little);

                try writer.writeInt(u64, self.receiver_services, .little);
                try writer.writeAll(&self.receiver_ip);
                try writer.writeInt(u16, self.receiver_port, .big);

                try writer.writeInt(u64, self.sender_services, .little);
                try writer.writeAll(&self.sender_ip);
                try writer.writeInt(u16, self.sender_port, .big);

                try writer.writeInt(u64, self.nonce, .little);
                std.debug.assert(self.user_agent.len < 0xfd); // It's supposed to be read as varint
                try writer.writeInt(u8, @intCast(self.user_agent.len), .little);
                try writer.writeAll(self.user_agent);
                try writer.writeInt(i32, self.start_height, .little);

                try writer.writeInt(u8, if (self.relay) 1 else 0, .big);
            }

            pub fn parse(data: []const u8, alloc: std.mem.Allocator) anyerror!ParseResult {
                var reader = Cursor.init(data);
                var res = ParseResult{
                    .value = Message{ .version = .{ .timestamp = 0, .user_agent = undefined } },
                    .bytes_read_count = 0,
                };

                const length = reader.readInt(u32, .little);
                res.bytes_read_count += 4;

                var chcksum: [4]u8 = undefined;
                reader.readBytes(&chcksum);
                res.bytes_read_count += 4;

                const payload_bytes = reader.data[reader.index..][0..length]; // for checksum
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

                // checksum validation
                var hash: [32]u8 = undefined;
                Sha256.hash(payload_bytes, &hash, .{});
                Sha256.hash(&hash, &hash, .{});
                const expected_checksum: []u8 = hash[0..4];
                if (!std.mem.eql(u8, &chcksum, expected_checksum)) {
                    return error.ChecksumMismatch;
                }

                return res;
            }

            pub fn deinit(self: @This(), alloc: std.mem.Allocator) void {
                alloc.free(self.user_agent);
            }
        },
        verack: struct {
            pub fn serialize(self: @This(), writer: std.io.AnyWriter) anyerror!void {
                _ = self;
                _ = writer;
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
            hash_start_block: u256,
            /// 0 means "as much as possible"
            hash_final_block: u256,

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
                    .value = .{ .getheaders = undefined },
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
            // @TODO should hold many blocks
            count: u32,
            data: Bitcoin.Block,

            pub fn serialize(self: @This(), writer: std.io.AnyWriter) anyerror!void {
                // @TODO thats unecessary copying, can we improve?
                std.debug.assert(self.count == 1);
                try Bitcoin.Aux.writeVarint(writer, self.count);
                var buffer: [80]u8 = undefined;
                const serialization = try self.data.serialize(&buffer);
                try writer.writeAll(serialization);
                try writer.writeInt(u8, 0, .little);
            }

            pub fn parse(data: []const u8, unused: std.mem.Allocator) anyerror!ParseResult {
                _ = unused;
                var cursor = Cursor.init(data);
                const starting_index = cursor.index;
                const count = cursor.readVarint();
                std.debug.assert(count == 1); // TODO
                var buffer: [80]u8 = undefined;
                cursor.readBytes(&buffer);
                std.debug.assert(cursor.readInt(u8, .little) == 0);
                const total_read: u32 = 80 + @as(u32, @intCast(cursor.index - starting_index));

                const block_res = try Bitcoin.Block.parse(&buffer);
                return .{
                    .value = .{ .headers = .{ .count = count, .data = block_res } },
                    .bytes_read_count = total_read,
                };
            }
        },

        // Enforce function signatures on each union tag (each protocol command)
        comptime {
            const T = Protocol.Message;

            const ExpectedFunction = struct {
                is_mandatory: bool,
                name: []const u8,
                return_type: type,
                params: []const type,
            };
            const expected_functions = .{
                ExpectedFunction{
                    .is_mandatory = true,
                    .name = "serialize",
                    .return_type = anyerror!void,
                    .params = &[_]type{ void, std.io.AnyWriter },
                },
                ExpectedFunction{
                    .is_mandatory = true,
                    .name = "parse",
                    .return_type = anyerror!Protocol.Message.ParseResult,
                    .params = &[_]type{ []const u8, std.mem.Allocator },
                },
                ExpectedFunction{
                    .is_mandatory = false,
                    .name = "deinit",
                    .return_type = void,
                    .params = &[_]type{ void, std.mem.Allocator },
                },
            };

            for (@typeInfo(T).@"union".fields) |field| {
                for (expected_functions) |expected| {
                    // check existance
                    if (!@hasDecl(field.type, expected.name)) {
                        if (expected.is_mandatory) {
                            var buf: [200]u8 = undefined;
                            @compileError(std.fmt.bufPrint(&buf, "A {} function is required for {}.{}", .{ expected.name, @typeName(T), field.name }) catch "E879234");
                        } else continue;
                    }

                    const fn_decl = @field(field.type, expected.name);
                    const fn_info = @typeInfo(@TypeOf(fn_decl)).@"fn";
                    const SignatureMismatch = struct {
                        fn throw() void {
                            var buf: [300]u8 = undefined;
                            @compileError(std.fmt.bufPrint(
                                &buf,
                                "The function {s}.{s}.{s} has the wrong signature. Should be: fn {s}({d}) {s} (also check parameter types)",
                                .{ @typeName(T), field.name, expected.name, expected.name, expected.params.len, @typeName(expected.return_type) },
                            ) catch "E1293485");
                        }
                    };

                    // check return_type
                    if (fn_info.return_type != expected.return_type)
                        SignatureMismatch.throw();

                    if (fn_info.params.len != expected.params.len)
                        SignatureMismatch.throw();

                    for (fn_info.params, expected.params) |p_actual, p_expected| {
                        if (p_expected == void) continue; // void means ignore
                        if (p_actual.type != p_expected)
                            SignatureMismatch.throw();
                    }
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

            // payload
            std.debug.assert(writer.context.pos == 16);
            // intentionally skipping 8 bytes cause we need payload to compute them
            var payload_buffer = buffer[24..];
            var payload_stream = std.io.fixedBufferStream(payload_buffer);
            switch (self.*) {
                inline else => |field| try field.serialize(payload_stream.writer().any()),
            }
            const payload_size = payload_stream.pos;

            // length
            try writer.writeInt(u32, @intCast(payload_size), .little);

            // checksum
            var hash: [32]u8 = undefined;
            Sha256.hash(payload_buffer[0..payload_size], &hash, .{});
            Sha256.hash(&hash, &hash, .{});
            try writer.writeAll(hash[0..4]);

            return buffer[0 .. writer.context.pos + payload_size];
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

            assert(res.bytes_read_count == 16);
            const first_zero_index: usize = for (command, 0..) |c, i| {
                if (c == 0) break i;
            } else 12;
            const tag_name = command[0..first_zero_index];
            var supported_command = false;
            inline for (@typeInfo(Message).@"union".fields) |field| {
                if (std.mem.eql(u8, field.name, tag_name)) {
                    supported_command = true;
                    const msg_parse_result = try field.type.parse(bytes[res.bytes_read_count..], alloc);
                    res.value = msg_parse_result.value;
                    res.bytes_read_count += msg_parse_result.bytes_read_count;
                }
            }

            if (!supported_command) return error.UnsupportedCommandReceived;

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
            std.log.err("Failed to connect to {}: {s}", .{ address, @errorName(err) });
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
        std.log.debug("Sending message \"{s}\" with following payload ({d} bytes):", .{ @tagName(message), data.len - Protocol.header_len });
        std.log.debug("{s}", .{std.fmt.fmtSliceHexLower(data[Protocol.header_len..])});
        connection.stream.writeAll(data) catch |err| {
            std.log.err("Failed to write to socket at {any}: {s}", .{ connection.peer_address, @errorName(err) });
            return error.SendError;
        };
    }

    /// Synchronously waits to receive bytes. Caller should call .deinit() on returned value
    pub fn readMessage(connection: Connection, alloc: std.mem.Allocator) !Protocol.Message {
        const header_len = Protocol.header_len;
        var buffer = ([1]u8{0} ** header_len) ++ ([1]u8{0} ** (1024 * 256));
        var header_slice = buffer[0..header_len];

        const read_count1 = connection.stream.readAtLeast(header_slice, header_len) catch |err| {
            std.log.err("Failed to read from socket at {any}: {s}", .{ connection.peer_address, @errorName(err) });
            return error.ReceiveError;
        };
        if (read_count1 < header_len) return error.ReceiveError;
        std.debug.assert(read_count1 == header_len);
        const payload_length = std.mem.readInt(u32, header_slice[16..][0..4], .little);
        const payload_slice = buffer[header_len..][0..payload_length];

        const read_count2 = connection.stream.readAtLeast(payload_slice, payload_length) catch |err| {
            std.log.err("Failed to read from socket at {any}: {s}", .{ connection.peer_address, @errorName(err) });
            return error.ReceiveError;
        };
        if (read_count2 < payload_length) return error.ReceiveError;

        std.log.debug("Received message \"{s}\" with the following payload ({d} bytes):", .{ header_slice[4..16], payload_length });
        std.log.debug("{s}", .{std.fmt.fmtSliceHexLower(payload_slice)});

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
