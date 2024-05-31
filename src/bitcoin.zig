// std
const std = @import("std");
const assert = std.debug.assert;
var allocator = std.heap.page_allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

// not managed dependencies
const c_ripemd = @cImport({
    @cInclude("ripemd.c");
});

// managed dependencies
const EllipticCurveLib = @import("elliptic-curve.zig");
const CryptLib = @import("cryptography.zig");
const Cursor = @import("cursor.zig").Cursor;

pub const Base58 = struct {
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // returns in what index we can start reading the ouput
    // reads bytes as big endian
    pub fn encode(bytes: []const u8, out: []u8) usize {
        if (bytes.len > 128) @panic("Base58.encode: bytes is too large, only up to 128 bytes supported");
        var bytes_extended: [128]u8 = undefined;
        if (bytes.len != 128)
            bytes_extended = [_]u8{0} ** 128;
        std.mem.copyForwards(u8, bytes_extended[(128 - bytes.len)..128], bytes);

        const bytes_as_u1024: u1024 = std.mem.readInt(u1024, &bytes_extended, .big);
        var remaining = bytes_as_u1024;
        var i = out.len;
        while (remaining > 0) {
            if (i == 0) std.debug.panic("Base58.encode: out is too small ({d} bytes) for the input {x}", .{ out.len, bytes_as_u1024 });
            i = i - 1;
            out[i] = alphabet[@intCast(remaining % 58)];
            remaining = remaining / 58;
        }
        return i;
    }

    // returns in what index we can start reading the ouput
    // writes out as big endian
    pub fn decode(bytes: []const u8, out: *[1024 / 8]u8) usize {
        var bytes_as_u1024: u1024 = 0;
        {
            var multiplier: u1024 = 1;
            var i = bytes.len;
            while (i > 0) : (i -= 1) {
                bytes_as_u1024 += increment: {
                    const algarism = bytes[i - 1];
                    const algarism_value: u1024 = for (alphabet, 0..) |symbol, j| {
                        if (symbol == algarism) break @intCast(j);
                    } else @panic("Base58.decode: invalid character");
                    break :increment algarism_value * multiplier;
                };
                const result = @mulWithOverflow(multiplier, @as(u1024, 58));
                if (result[1] == 1) unreachable;
                multiplier = result[0];
            }
        }

        var i = out.len;
        while (i > 0) : (i -= 1) {
            out[i - 1] = @as(u8, @truncate(bytes_as_u1024));
            bytes_as_u1024 >>= 8;
            if (bytes_as_u1024 == 0) return i - 1;
        }
        return 0;
    }
};

pub fn btcAddress(pubkey: EllipticCurveLib.CurvePoint(u256), out: *const []u8, testnet: bool) usize {
    var serializedPoint: [33]u8 = undefined;
    pubkey.serialize(true, &serializedPoint);
    var sha256_1: [33]u8 = undefined;
    sha256_1[32] = 0x00;
    Sha256.hash(&serializedPoint, sha256_1[0..32], .{});
    var hash160: [21]u8 = undefined;
    c_ripemd.calc_hash(&sha256_1, hash160[1..]);
    hash160[0] = if (testnet) 0x6f else 0x00;
    var sha256_2: [32]u8 = undefined;
    Sha256.hash(&hash160, &sha256_2, .{});
    var sha256_3: [32]u8 = undefined;
    Sha256.hash(&sha256_2, &sha256_3, .{});
    var checksum: [4]u8 = undefined;
    std.mem.copyForwards(u8, &checksum, sha256_3[0..4]);
    const address = hash160 ++ checksum;
    const start = Base58.encode(&address, out.*[0..]);
    if (testnet) return start;
    out.*[start - 1] = '1';
    return start - 1;
}

pub const Tx = struct {
    version: u32,
    inputs: []TxInput,
    outputs: []TxOutput,
    locktime: u32,

    pub const TxInput = struct {
        txid: u256,
        index: u32,
        script_sig: []u8,
        sequence: u32,
    };
    pub const TxOutput = struct {
        amount: u64,
        script_pubkey: []u8,
    };

    pub fn serialize(self: *Tx) ![]u8 {
        var bytes = try std.ArrayList(u8).initCapacity(allocator, 100);
        defer bytes.deinit();
        const Aux = struct {
            pub fn writeVarint(stream: std.io.AnyWriter, value: u32) !void {
                if (value < 0xfd) {
                    try stream.writeInt(u8, @intCast(value), .little);
                } else if (value <= 0xffff) {
                    try stream.writeByte(0xfd);
                    try stream.writeInt(u16, @intCast(value), .little);
                } else if (value < 0xffffff) {
                    try stream.writeByte(0xfe);
                    try stream.writeInt(u24, @intCast(value), .little);
                } else {
                    try stream.writeByte(0xff);
                    try stream.writeInt(u32, @intCast(value), .little);
                }
            }
        };

        try bytes.writer().writeInt(u32, self.version, .little);
        try Aux.writeVarint(bytes.writer().any(), @intCast(self.inputs.len));
        for (self.inputs) |input| {
            try bytes.writer().writeInt(u256, input.txid, .little);
            try bytes.writer().writeInt(u32, input.index, .little);
            //try bytes.writer().writeVarint(output.script_pubkey.len);
            try bytes.writer().writeAll(input.script_sig);
            try bytes.writer().writeInt(u32, input.sequence, .little);
        }

        try Aux.writeVarint(bytes.writer().any(), @intCast(self.outputs.len));
        for (self.outputs) |output| {
            try bytes.writer().writeInt(u64, output.amount, .little);
            //try bytes.writer().writeVarint(output.script_pubkey.len);
            try bytes.writer().writeAll(output.script_pubkey);
        }
        try bytes.writer().writeInt(u32, self.locktime, .little);
        return bytes.toOwnedSlice();
    }

    pub fn parse(data: []u8) !Tx {
        var cursor = Cursor.init(data);
        var tx: Tx = undefined;

        tx.version = cursor.readInt(u32);

        tx.inputs = inputs: {
            const n_inputs = cursor.readVarint();
            const inputs = try allocator.alloc(TxInput, n_inputs);
            for (inputs) |*input| {
                input.txid = cursor.readInt(u256);
                input.index = cursor.readInt(u32);
                input.script_sig = script_sig: {
                    const script_sig = try allocator.alloc(u8, cursor.readVarint());
                    cursor.readBytes(script_sig);
                    break :script_sig script_sig;
                };
                input.sequence = cursor.readInt(u32);
            }
            break :inputs inputs;
        };

        tx.outputs = outputs: {
            const n_outputs = cursor.readVarint();
            const outputs = try allocator.alloc(TxOutput, n_outputs);
            for (outputs) |*output| {
                output.amount = cursor.readInt(u64);
                output.script_pubkey = script_pubkey: {
                    const script_pubkey = try allocator.alloc(u8, cursor.readVarint());
                    cursor.readBytes(script_pubkey);
                    break :script_pubkey script_pubkey;
                };
            }
            break :outputs outputs;
        };

        tx.locktime = cursor.readInt(u32);

        return tx;
    }
};

pub const Script = struct {
    const Stack = struct {
        data: []u8,

        /// Points to first empty index
        top: usize = 0,

        //Same behaviour as Bitcoin Core:
        //   "Numeric opcodes (OP_ADD, etc) are restricted to operating on 4-byte integers.
        //    The semantics are subtle, though: operands must be in the range [-2^31 +1...2^31 -1],
        //    but results may overflow (and are valid as long as they are not used in a subsequent
        //    numeric operation). CScriptNum enforces those semantics by storing results as
        //    an int64 and allowing out-of-range values to be returned as a vector of bytes but
        //    throwing an exception if arithmetic is done or the result is interpreted as an integer."
        const Int = i64;

        const Self = @This();

        fn init(size: usize) !Self {
            return .{ .data = try allocator.alloc(u8, size) };
        }

        fn deinit(self: *Self) void {
            allocator.free(self.data);
        }

        fn push(self: *Self, value: []const u8) void {
            std.mem.copyForwards(u8, self.data[self.top..][0..value.len], value);
            self.top += value.len;
            if (value.len > std.math.maxInt(u8))
                @panic("Not handling this case yet: pushing more than 255 bytes");
            self.data[self.top] = @intCast(value.len);
            self.top += 1;
        }

        fn pushInt(self: *Self, value: Self.Int) void {
            push(self, std.mem.asBytes(&value));
        }

        // @TODO migrate all code to popSafe
        fn pop(self: *Self) PopError![]u8 {
            if (self.top == 0)
                return error.EmptyStack;
            self.top -= 1;
            const next_byte = self.data[self.top];
            if (self.data.len < next_byte)
                return error.Corrupted;
            if (next_byte == 0)
                return &[_]u8{};
            const ret = self.data[self.top - next_byte .. self.top];
            self.top -= next_byte;
            return ret;
        }
        const PopError = error{ EmptyStack, Corrupted };

        fn popSafe(self: *Self, out: []u8) PopSafeError!void {
            const popped = try self.pop();
            if (popped.len > out.len)
                return error.OutBufferTooSmall;
            std.mem.copyForwards(u8, out, popped);
        }
        const PopSafeError = PopError || error{OutBufferTooSmall};

        fn popInt(self: *Self) PopIntError!Self.Int {
            const data = try self.pop();
            if (data.len > 4) {
                return error.NotAnOperableInteger;
            } else if (data.len == 4) {
                const data_as_unsigned: *u32 = @ptrCast(@alignCast(data));
                const sign_as_int: Self.Int = if (data_as_unsigned.* & 0x80000000 != 0) -1 else 1;
                const value: Self.Int = (data_as_unsigned.* & 0x7FFFFFFF);

                return sign_as_int * value;
            } else if (data.len == 1) {
                // when less than 4 bytes, the value can't be signed
                return @as(Self.Int, @intCast(data[0]));
            } else {
                @panic("Not handling this case yet: popping more than 1 but less than 4 bytes");
            }
        }
        const PopIntError = PopError || error{NotAnOperableInteger};

        // Only false when top value is existent AND not true.
        // Zero, negative zero and empty array are all treated as false.
        // Anything else is treated as true.
        fn verify(self: *Stack) bool {
            const value = self.pop() catch |err| return err == error.EmptyStack;
            const all_zero = for (value, 0..) |byte, index| {
                if (index == value.len - 1 and byte == 0x80) continue; // account for negative zero
                if (byte != 0) break false;
            } else true;
            if (value.len == 0 or all_zero) {
                return false;
            }
            return true;
        }
    };

    // This must not be an enum. An enum is a type. I want constants of type u8
    pub const Opcode = struct {
        pub const OP_0: u8 = 0;
        pub const OP_1: u8 = 0x51;
        pub const OP_2: u8 = 0x52;
        pub const OP_3: u8 = 0x53;
        pub const OP_4: u8 = 0x54;
        pub const OP_5: u8 = 0x55;
        pub const OP_6: u8 = 0x56;
        pub const OP_7: u8 = 0x57;
        pub const OP_8: u8 = 0x58;
        pub const OP_9: u8 = 0x59;
        pub const OP_10: u8 = 0x5a;
        pub const OP_11: u8 = 0x5b;
        pub const OP_12: u8 = 0x5c;
        pub const OP_13: u8 = 0x5d;
        pub const OP_14: u8 = 0x5e;
        pub const OP_15: u8 = 0x5f;
        pub const OP_16: u8 = 0x60;
        pub const OP_PUSHDATA1: u8 = 0x4c;
        pub const OP_PUSHDATA2: u8 = 0x4d;
        pub const OP_PUSHDATA4: u8 = 0x4e;
        pub const OP_VERIFY: u8 = 0x69;
        pub const OP_2DUP: u8 = 0x6e;
        pub const OP_DUP: u8 = 0x76;
        pub const OP_EQUAL: u8 = 0x87;
        pub const OP_EQUALVERIFY: u8 = 0x88;
        pub const OP_NOT: u8 = 0x91;
        pub const OP_ADD: u8 = 0x93;
        pub const OP_SUB: u8 = 0x94;
        pub const OP_SHA256: u8 = 0xa8;
        pub const OP_HASH160: u8 = 0xa9;
        pub const OP_CHECKSIG: u8 = 0xac;
    };

    pub fn run(script: []const u8, stack: *Stack, transaction: ?*Tx, input_index: ?usize) !void {
        const Op = Opcode;
        var scriptReader = Cursor.init(script);
        while (!scriptReader.ended()) {
            const opcode = scriptReader.readInt(u8);
            switch (opcode) {
                0x01...0x4b => { // Data
                    stack.push(script[scriptReader.index..][0..opcode]);
                    scriptReader.index += @intCast(opcode);
                },
                Op.OP_0 => {
                    stack.push(&[_]u8{});
                },
                Op.OP_1...Op.OP_16 => { // OP_1 to OP_16
                    stack.push(&[1]u8{opcode - 0x50});
                },
                Op.OP_PUSHDATA1 => {
                    const size = scriptReader.readInt(u8);
                    stack.push(script[scriptReader.index..][0..size]);
                    scriptReader.index += @intCast(size);
                },
                Op.OP_VERIFY => {
                    if (!stack.verify())
                        return error.VerifyFailed;
                },
                Op.OP_2DUP => {
                    const a: []u8 = stack.pop() catch return error.BadScript;
                    const b: []u8 = stack.pop() catch return error.BadScript;
                    stack.push(a);
                    stack.push(b);
                    stack.push(a);
                    stack.push(b);
                },
                Op.OP_DUP => {
                    const value: []u8 = stack.pop() catch return error.BadScript;
                    stack.push(value);
                    stack.push(value);
                },
                Op.OP_EQUAL => {
                    const a: []u8 = stack.pop() catch return error.BadScript;
                    const b: []u8 = stack.pop() catch return error.BadScript;
                    const eq: u8 = if (std.mem.eql(u8, a, b)) 1 else 0;
                    stack.push(&[1]u8{eq});
                },
                Op.OP_EQUALVERIFY => {
                    const a: []u8 = stack.pop() catch return error.BadScript;
                    const b: []u8 = stack.pop() catch return error.BadScript;
                    if (!std.mem.eql(u8, a, b)) {
                        return error.VerifyFailed;
                    }
                },
                Op.OP_NOT => {
                    const value: []u8 = stack.pop() catch return error.BadScript;
                    const equals_zero: u8 = for (value) |byte| {
                        if (byte != 0) break 0;
                    } else 1;
                    stack.push(&[1]u8{equals_zero});
                },
                Op.OP_ADD => {
                    const a: i64 = stack.popInt() catch return error.BadScript;
                    const b: i64 = stack.popInt() catch return error.BadScript;
                    const value: i64 = a + b;
                    stack.pushInt(value);
                },
                Op.OP_SUB => {
                    const a: i64 = stack.popInt() catch return error.BadScript;
                    const b: i64 = stack.popInt() catch return error.BadScript;
                    const value: i64 = a - b;
                    stack.pushInt(value);
                },
                Op.OP_SHA256 => {
                    const value: []u8 = stack.pop() catch return error.BadScript;
                    var value_hash: [32]u8 = undefined;
                    Sha256.hash(value, &value_hash, .{});
                    stack.push(&value_hash);
                },
                Op.OP_HASH160 => {
                    var value: [512]u8 = [_]u8{0} ** 512;
                    stack.popSafe(&value) catch |err| {
                        if (err == error.OutBufferTooSmall) unreachable;
                        return error.BadScript;
                    };
                    assert(value[value.len - 1] == 0);
                    var value_hash: [20]u8 = undefined;
                    c_ripemd.calc_hash(@ptrCast(&value), &value_hash);
                    stack.push(&value_hash);
                },
                Op.OP_CHECKSIG => {
                    // @TODO consider OP_CODESEPARATOR and occurrences of sig
                    if (transaction == null or input_index == null) @panic("Calling checksig without a transaction or index");
                    const pubkey: []u8 = stack.pop() catch return error.BadScript;
                    var sig: []u8 = stack.pop() catch return error.BadScript;
                    const hashtype = sig[sig.len - 1];
                    sig = sig[0 .. sig.len - 1];

                    const txCopy = txCopy: {
                        var temp: *Tx = try allocator.create(Tx);
                        temp.* = transaction.?.*;
                        temp.outputs = try allocator.dupe(Tx.TxOutput, transaction.?.outputs);
                        temp.inputs = try allocator.dupe(Tx.TxInput, transaction.?.inputs);
                        for (0..transaction.?.inputs.len) |i| {
                            if (i == input_index) {
                                temp.inputs[i].script_sig = try allocator.dupe(u8, script);
                            } else {
                                temp.inputs[i].script_sig = try allocator.alloc(u8, 1);
                                temp.inputs[i].script_sig[0] = 0x00;
                            }
                        }
                        break :txCopy temp;
                    };
                    defer {
                        for (txCopy.inputs) |in| allocator.free(in.script_sig);
                        allocator.free(txCopy.inputs);
                        allocator.free(txCopy.outputs);
                        allocator.destroy(txCopy);
                    }

                    const txCopyBytes = try txCopy.serialize();
                    const to_hash = try std.mem.concat(allocator, u8, &[_][]const u8{ txCopyBytes, &[4]u8{ hashtype, 0, 0, 0 } });
                    const z = CryptLib.hashAsU256(to_hash);
                    const pubkey_parsed = EllipticCurveLib.CurvePoint(u256).parse(pubkey, CryptLib.secp256k1_p, CryptLib.G.a, CryptLib.G.b);
                    if (CryptLib.verify(z, pubkey_parsed, CryptLib.Signature.parse(sig))) {
                        stack.push(&[1]u8{1});
                    } else {
                        stack.push(&[1]u8{0});
                    }
                },
                else => {
                    const msg = std.fmt.allocPrint(allocator, "Opcode {} not implemented\n", .{opcode}) catch @panic("While running a Script, a not implemented Opcode was found");
                    @panic(msg);
                },
            }
        }
    }

    pub fn validate(scriptSig: []const u8, scriptPubKey: []const u8, transaction: ?*Tx, input_index: ?usize) !bool {
        var stack = try Stack.init(scriptSig.len + scriptPubKey.len); // @TODO is this reasonable?
        defer stack.deinit();

        @This().run(scriptSig, &stack, transaction, input_index) catch return false;
        @This().run(scriptPubKey, &stack, transaction, input_index) catch return false;

        return stack.verify();
    }
};

//#region TESTS #########################################################################

const expect = std.testing.expect;

test "base58 encoding and decoding" {
    const u8_array = [8]u8{ 0x00, 0x00, 0x04, 0x09, 0x0a, 0x0f, 0x1a, 0xff };
    var encoded_u8_array: [10]u8 = undefined;
    const start = Base58.encode(&u8_array, &encoded_u8_array);
    try expect(std.mem.eql(u8, encoded_u8_array[start..], "31Yr1PVY"));

    var decoded: [128]u8 = undefined;
    const start_d = Base58.decode(encoded_u8_array[start..], &decoded);
    try expect(std.mem.eql(u8, decoded[start_d..], u8_array[2..]));
}

test "btc address" {
    const prvk = 0x5da1cb5b4282e3f5c2314df81a3711fa7f0217401de5f72da0ab4906fab04f4c;
    const pubk = CryptLib.G.muli(prvk);
    var out: [40]u8 = undefined;
    const start = btcAddress(pubk, &out[0..], false);
    try expect(std.mem.eql(u8, out[start..], "1GHqmiofmT3PgrZDf7fcq632xybfg6onG4"));
}

test "parse transaction" {
    // zig fmt: off
    var transaction_bytes = [_]u8{
        0x01, 0x00, 0x00, 0x00, // version (constant)
        0x01, // number of inputs
            // 32 bytes of TXID
            0x7b, 0x1e, 0xab, 0xe0, 0x20, 0x9b, 0x1f, 0xe7, 0x94, 0x12, 0x45, 0x75, 0xef, 0x80, 0x70, 0x57, 0xc7, 0x7a, 0xda, 0x21, 0x38, 0xae, 0x4f, 0xa8, 0xd6, 0xc4, 0xde, 0x03, 0x98, 0xa1, 0x4f, 0x3f,
            0x00, 0x00, 0x00, 0x00, // output index
            0x49, // bytes of script signature
                0x48, 0x30, 0x45, 0x02, 0x21, 0x00, 0x89, 0x49, 0xf0, 0xcb, 0x40, 0x00, 0x94, 0xad, 0x2b, 0x5e, 0xb3, 0x99, 0xd5, 0x9d, 0x01, 0xc1, 0x4d, 0x73, 0xd8, 0xfe, 0x6e, 0x96, 0xdf, 0x1a, 0x71, 0x50, 0xde, 0xb3, 0x88, 0xab, 0x89, 0x35, 0x02, 0x20, 0x79, 0x65, 0x60, 0x90, 0xd7, 0xf6, 0xba, 0xc4, 0xc9, 0xa9, 0x4e, 0x0a, 0xad, 0x31, 0x1a, 0x42, 0x68, 0xe0, 0x82, 0xa7, 0x25, 0xf8, 0xae, 0xae, 0x05, 0x73, 0xfb, 0x12, 0xff, 0x86, 0x6a, 0x5f, 0x01,
            0xff, 0xff, 0xff, 0xff, // sequence
        0x01, // number of outputs
            0xf0, 0xca, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, // amount
            0x19, // bytes of script pubkey
                0x76, 0xa9, 0x14, 0xcb, 0xc2, 0x0a, 0x76, 0x64, 0xf2, 0xf6, 0x9e, 0x53, 0x55, 0xaa, 0x42, 0x70, 0x45, 0xbc, 0x15, 0xe7, 0xc6, 0xc7, 0x72, 0x88, 0xac,
        0x00, 0x00, 0x00, 0x00 // locktime
    };
    // zig fmt: on
    const transaction = try Tx.parse(transaction_bytes[0..transaction_bytes.len]);
    _ = transaction;
}

test "Basic script" {
    const answer = "And he answering said, Thou shalt love the Lord thy God with all thy heart, and with all thy soul, and with all thy strength, and with all thy mind; and thy neighbour as thyself.";
    const answer_hash = answer_hash: {
        var buf: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(answer, &buf, .{});
        break :answer_hash buf;
    };
    const Op = Script.Opcode;
    const script_pub_key = [_]u8{Op.OP_SHA256} ++ [1]u8{answer_hash.len} ++ answer_hash ++ [_]u8{ Op.OP_EQUAL, Op.OP_VERIFY };
    const script_sig = [_]u8{Op.OP_PUSHDATA1} ++ [1]u8{answer.len} ++ answer.*;
    try expect(try Script.validate(&script_sig, &script_pub_key, null, null));
}

//#endregion
