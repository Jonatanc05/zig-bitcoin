// std
const std = @import("std");
const assert = std.debug.assert;
var allocator = std.heap.page_allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

// managed dependencies
const Cursor = @import("cursor.zig").Cursor;
const Bitcoin = @import("bitcoin.zig");

const genesis_block_hash: u256 = 0xdeadbeef;

fn ipv4_as_ipv6(ipv4: [4]u8) [16]u8 {
    return [1]u8{0} ** 10 ++ [2]u8{ 0xff, 0xff } ++ ipv4;
}

pub const Protocol = struct {
    const magic_mainnet = 0xf9beb4d9;
    const magic_testnet = 0x0b110907;

    /// Union for any message accepted by the Bitcoin protocol and its corresponding payload as data
    pub const Message = union(enum) {
        ping: struct {
            nonce: u64,

            pub fn serialize(self: @This(), writer: std.io.AnyWriter) !void {
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

            pub fn parse(data: []const u8) !ParseResult {
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

            pub fn serialize(self: @This(), writer: std.io.AnyWriter) !void {
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

            pub fn parse(data: []const u8) !ParseResult {
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
            version: i32 = 70014,
            services: u64 = 0,
            timestamp: i64,
            receiver_services: u64 = 0,
            receiver_ip: [16]u8 = [1]u8{0} ** 16,
            receiver_port: u16 = 8333,
            sender_services: u64 = 0,
            sender_ip: [16]u8 = ipv4_as_ipv6([4]u8{ 127, 0, 0, 1 }),
            sender_port: u16 = 8333,
            nonce: u64 = 0x1f297b45,
            user_agent: []const u8 = "Zignode",
            start_height: i32 = 0,
            relay: bool = false,

            pub fn serialize(self: @This(), writer: std.io.AnyWriter) !void {
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
                    try bufwriter.writeInt(u8, @intCast(self.user_agent.len), .little); // TODO check size bc this is supposed to be a varint
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

            pub fn parse(data: []const u8) !ParseResult {
                var reader = Cursor.init(data);
                var res = ParseResult{
                    .value = Message{ .version = .{ .timestamp = 0 } },
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
                out.user_agent = try allocator.dupe(u8, buffer[0..user_agent_len]);
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
        },
        verack: struct {
            pub fn serialize(self: @This(), writer: std.io.AnyWriter) !void {
                _ = self;
                const serialized = [_]u8{ 0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x61, 0x63, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2 };
                try writer.writeAll(&serialized);
            }

            pub fn parse(data: []const u8) !ParseResult {
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

            pub fn serialize(self: @This(), writer: std.io.AnyWriter) !void {
                try writer.writeInt(i32, self.version, .little);
                try Bitcoin.Aux.writeVarint(writer, self.hash_count);
                try writer.writeInt(u256, self.hash_start_block, .little);
                try writer.writeInt(u256, self.hash_final_block, .little);
            }

            pub fn parse(data: []const u8) !ParseResult {
                var cursor = Cursor.init(data);
                var res = ParseResult { .value = .{ .getheaders = .{}}, .bytes_read_count = 0 };

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

            pub fn serialize(self: @This(), writer: std.io.AnyWriter) !void {
                const serialization = try self.data.serialize(allocator);
                defer allocator.free(serialization);
                try writer.writeAll(serialization);
                try Bitcoin.Aux.writeVarint(writer, self.count);
            }

            pub fn parse(data: []const u8) !ParseResult {
                const block_res = try Bitcoin.Block.parse(data);
                assert(@sizeOf(Bitcoin.Block) == 80);
                var cursor = Cursor.init(data[80..]);
                const starting_index = cursor.index;
                const count = cursor.readVarint();
                const total_read: u32 = 80 + @as(u32, @intCast(cursor.index - starting_index));
                return .{
                    .value = .{ .headers = .{ .data = block_res, .count = count }},
                    .bytes_read_count = total_read,
                };
            }
        },

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
                //.ping => |ping| try ping.serialize(writer.any()),
                //.pong => |pong| try pong.serialize(writer.any()),
                //.version => |version| try version.serialize(writer.any()),
                inline else => |field| try field.serialize(writer.any()),
            }
            return buffer[0..writer.context.pos];
        }

        const ParseResult = struct { value: Message, bytes_read_count: u32 };
        pub fn parse(bytes: []u8) !ParseResult {
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
            inline for (@typeInfo(Message).@"union".fields) |f| {
                if (std.mem.eql(u8, f.name, tagName)) {
                    const version_res = try f.type.parse(bytes[res.bytes_read_count..]);
                    res.value = version_res.value;
                    res.bytes_read_count += version_res.bytes_read_count;
                }
            }

            return res;
        }
    };

    pub fn checksum(bytes: []u8) [4]u8 {
        var hash: [32]u8 = undefined;
        Sha256.hash(bytes, &hash, .{});
        Sha256.hash(&hash, &hash, .{});
        return hash[0..4];
    }
};

//#region TESTS #########################################################################

const expect = std.testing.expect;

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

    const parsed_res = (try Protocol.Message.parse(res)).value;
    var buffer2 = [_]u8{0} ** 32;
    const serialized_parsed_res = try parsed_res.serialize(&buffer2);

    try std.testing.expectEqualSlices(
        u8,
        res,
        serialized_parsed_res,
    );
}

test "protocol: handshake and version" {
    // Turn this on to see logs printed to stderr (this causes test to fail)
    const debug_log = false;
    //const host = "58.96.123.120"; // from bitcoin core's nodes_main.txt
    const host = "74.220.255.190"; // from bitcoin core's nodes_main.txt
    const port = 8333;
    const stream = std.net.tcpConnectToHost(allocator, host, port) catch |err| {
        std.debug.print("failed to connect to {s}:{d}: {s}\n", .{ host, port, @errorName(err) });
        return err;
    };
    const timestamp = std.time.timestamp();
    const message = Protocol.Message{ .version = .{
        .timestamp = timestamp,
        .nonce = @intCast(timestamp),
        .start_height = 0,
    } };
    var buffer: [1024]u8 = undefined;
    const data = try message.serialize(&buffer);
    stream.writeAll(data) catch |err| {
        std.debug.print("failed to write to socket at {s}:{d}: {s}\n", .{ host, port, @errorName(err) });
        return err;
    };
    if (debug_log)
        std.debug.print("\nsent {d} bytes (version): {s}\n", .{ data.len, std.fmt.fmtSliceHexLower(data) });
    buffer = [1]u8{0} ** 1024;
    //buffer = [_]u8{ 0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0xb9, 0x7b, 0x2a, 0xbb, 0x80, 0x11, 0x01, 0x00, 0x0d, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6e, 0xf0, 0xa7, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xba, 0xce, 0xb0, 0x66, 0xd1, 0x86, 0x0d, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x40, 0x12, 0xf7, 0x95, 0xb6, 0x6f, 0x06, 0x10, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68, 0x69, 0x3a, 0x32, 0x36, 0x2e, 0x31, 0x2e, 0x30, 0x2f, 0x09, 0x79, 0x0d, 0x00, 0x01, 0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x61, 0x63, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2 } ++ [1]u8{0} ** (1024 - 150);
    //const bytes_read_count = 150;
    const bytes_read_count = stream.read(&buffer) catch |err| {
        std.debug.print("failed to read from socket at {s}:{d}: {s}\n", .{ host, port, @errorName(err) });
        return err;
    };
    const bytes_read = buffer[0..bytes_read_count];
    if (debug_log)
        std.debug.print("\nreceived {d} bytes: {s}\n", .{ bytes_read.len, std.fmt.fmtSliceHexLower(bytes_read) });

    var bytes_parsed_count: u32 = 0;
    while (bytes_parsed_count < bytes_read_count) {
        if (debug_log)
            std.debug.print("parsed {} so far\n", .{bytes_parsed_count});
        const result = try Protocol.Message.parse(bytes_read[bytes_parsed_count..]);
        const message_received = result.value;
        if (debug_log)
            std.debug.print("\n\nMessage received: {any}\n\n", .{message_received});

        bytes_parsed_count += result.bytes_read_count;
    }
    if (debug_log)
        std.debug.print("parsed {} bytes out of {}\n", .{ bytes_parsed_count, bytes_read_count });
}

//#endregion
