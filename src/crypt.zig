const c_ripemd = @cImport({
    @cInclude("ripemd.c");
});
const std = @import("std");
const assert = std.debug.assert;
var allocator = std.heap.page_allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

const EllipticCurveLib = @import("elliptic-curve.zig");
const modpow = EllipticCurveLib.modpow;
const FieldElement = EllipticCurveLib.FieldElement;
const CurvePoint = EllipticCurveLib.CurvePoint;

comptime {
    if (EllipticCurveLib.NumberType != u256 or EllipticCurveLib.MulExtendedNumberType != u512) {
        // This is because we use secp256k1
        @compileError("Only NumberType = u256 is supported");
    }
}

const Cursor = struct {
    data: []const u8,
    index: usize = 0,

    fn init(data: []const u8) Cursor {
        return Cursor{ .data = data };
    }

    fn ended(self: *Cursor) bool {
        return self.index == self.data.len;
    }

    fn assertCanRead(self: *Cursor, n_bytes: usize) void {
        if (self.index + n_bytes > self.data.len) {
            const message = std.fmt.allocPrint(
                allocator,
                "Trying to read {} bytes at index {} when the data is only {} bytes (only {} could be read)",
                .{ n_bytes, self.index, self.data.len, self.data.len - self.index },
            ) catch unreachable;
            @panic(message);
        }
    }

    // Little endian
    fn readInt(self: *Cursor, comptime T: type) T {
        comptime assert(@typeInfo(T).Int.signedness == .unsigned);
        self.assertCanRead(@sizeOf(T));
        const n_bytes = @divExact(@typeInfo(T).Int.bits, 8);
        const ret = std.mem.readInt(T, self.data[self.index..][0..n_bytes], .little);
        self.index += @sizeOf(T);
        return ret;
    }

    fn readVarint(self: *Cursor) u32 {
        const first_byte = self.readInt(u8);
        return switch (first_byte) {
            else => @intCast(first_byte),
            0xfd => return @intCast(self.readInt(u16)),
            0xfe => return @intCast(self.readInt(u24)),
            0xff => return @intCast(self.readInt(u32)),
        };
    }

    fn readBytes(self: *Cursor, dest: []u8) void {
        self.assertCanRead(dest.len);
        std.mem.copyForwards(u8, dest, self.data[self.index..][0..dest.len]);
        self.index += dest.len;
    }
};

//#region CRYPTOGRAPHY #########################################################################

const secp256k1_a = 0;
const secp256k1_b = 7;
const secp256k1_a_fe = FieldElement.init(secp256k1_a, secp256k1_p);
const secp256k1_b_fe = FieldElement.init(secp256k1_b, secp256k1_p);

pub const G = CurvePoint.init(
    FieldElement.init(0x79be667e_f9dcbbac_55a06295_ce870b07_029bfcdb_2dce28d9_59f2815b_16f81798, secp256k1_p),
    FieldElement.init(0x483ada77_26a3c465_5da4fbfc_0e1108a8_fd17b448_a6855419_9c47d08f_fb10d4b8, secp256k1_p),
    secp256k1_a_fe,
    secp256k1_b_fe,
);

pub const secp256k1_p = 0xffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_fffffffe_fffffc2f;
pub const secp256k1_n = 0xffffffff_ffffffff_ffffffff_fffffffe_baaedce6_af48a03b_bfd25e8c_d0364141;

pub const Signature = struct {
    r: u256,
    s: u256,
};

pub fn hashAsU256(message: []const u8) u256 {
    var z_bytes: [32]u8 = undefined;
    Sha256.hash(message, &z_bytes, .{});
    return std.mem.readInt(u256, &z_bytes, .big);
}

pub fn generateKeyPair() struct { pubk: CurvePoint, prvk: u256 } {
    const e = std.crypto.random.int(u256);
    const P = G.muli(e);
    return .{ .pubk = P, .prvk = e };
}

pub fn sign(z: u256, e: u256) Signature {
    const k = std.crypto.random.int(u256);
    const r = G.muli(k).x.?.value;
    const k_inv = modpow(k, secp256k1_n - 2, secp256k1_n);
    const s: u256 = s_calc: { // s = (r * e + z) * k_inv (mod n)
        var temp: u512 = r;
        temp = temp * e;
        temp = @mod(temp, secp256k1_n);
        temp = temp + z;
        temp = @mod(temp, secp256k1_n);
        temp = temp * k_inv;
        temp = @mod(temp, secp256k1_n);
        break :s_calc @intCast(temp);
    };
    return Signature{ .r = r, .s = s };
}

pub fn verify(z: u256, P: CurvePoint, sig: Signature) bool {
    const s_inv = modpow(sig.s, secp256k1_n - 2, secp256k1_n);

    const u: u256 = u_calc: { // u = z * s_inv (mod n)
        var temp: u512 = z;
        temp = temp * s_inv;
        temp = @mod(temp, secp256k1_n);
        break :u_calc @intCast(temp);
    };

    const v: u256 = v_calc: { // v = r * s_inv (mod n)
        var temp: u512 = sig.r;
        temp = temp * s_inv;
        temp = @mod(temp, secp256k1_n);
        break :v_calc @intCast(temp);
    };

    return G.muli(u).add(P.muli(v)).x.?.value == sig.r;
}

//#endregion

//#region SERIALIZATION #########################################################################

pub fn serializePoint(point: CurvePoint, comptime compressed: bool, out: *[if (compressed) 33 else 65]u8) void {
    assert(point.x != null and point.y != null); // @TODO infinity
    assert(point.x.?.prime == secp256k1_p);
    var x_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &x_bytes, point.x.?.value, .big);

    if (compressed) {
        assert(out.len >= 33);
        if (point.y.?.value % 2 == 0) {
            out.* = [1]u8{0x02} ++ x_bytes;
        } else {
            out.* = [1]u8{0x03} ++ x_bytes;
        }
    } else {
        assert(out.len >= 65);
        var y_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &y_bytes, point.y.?.value, .big);
        out.* = [1]u8{0x04} ++ x_bytes ++ y_bytes;
    }
}

pub fn parsePoint(bytes: []const u8) CurvePoint {
    assert(bytes.len > 0);
    switch (bytes[0]) {
        0x02, 0x03 => {
            assert(bytes.len == 33);
            const x = FieldElement.init(
                std.mem.readInt(u256, bytes[1..33], .big),
                secp256k1_p,
            );
            const y_squared = x.pow(3).add(secp256k1_b_fe);
            const y = modpow(y_squared.value, @divFloor(secp256k1_p + 1, 4), secp256k1_p);
            const even_y = if (y % 2 == 0) FieldElement.init(y, secp256k1_p) else FieldElement.init(secp256k1_p - y, secp256k1_p);
            const odd_y = if (y % 2 == 1) FieldElement.init(y, secp256k1_p) else FieldElement.init(secp256k1_p - y, secp256k1_p);
            if (bytes[0] == 0x02) {
                return CurvePoint.init(x, even_y, secp256k1_a_fe, secp256k1_b_fe);
            } else if (bytes[0] == 0x03) {
                return CurvePoint.init(x, odd_y, secp256k1_a_fe, secp256k1_b_fe);
            } else unreachable;
        },
        0x04 => {
            assert(bytes.len == 65);
            const x = FieldElement.init(std.mem.readInt(u256, bytes[1..33], .big), secp256k1_p);
            const y = FieldElement.init(std.mem.readInt(u256, bytes[33..65], .big), secp256k1_p);
            return CurvePoint.init(x, y, secp256k1_a_fe, secp256k1_b_fe);
        },
        else => unreachable,
    }
}

pub fn serializeSignature(sig: Signature, out: *[72]u8) void {
    const bytes_0_to_5 = [_]u8{ 0x30, 0x46, 0x02, 0x21, 0x00 };
    std.mem.copyForwards(u8, out[0..5], &bytes_0_to_5);
    std.mem.writeInt(u256, out[5..37], sig.r, .big);
    const bytes_37_to_39 = [_]u8{ 0x02, 0x21 };
    std.mem.copyForwards(u8, out[37..39], &bytes_37_to_39);
    std.mem.writeInt(u256, out[39..71], sig.s, .big);
}

pub fn parseSignature(bytes: []const u8) Signature {
    assert(bytes.len == 72);
    assert(bytes[0] == 0x30 and bytes[1] == 0x46);
    return .{
        .r = std.mem.readInt(u256, bytes[5..37], .big),
        .s = std.mem.readInt(u256, bytes[39..71], .big),
    };
}

pub fn base58Encode(bytes: []const u8, out: []u8) usize {
    if (bytes.len > 128) @panic("base58Encode: bytes is too large, only up to 128 bytes supported");
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    var bytes_extended: [128]u8 = undefined;
    if (bytes.len != 128)
        bytes_extended = [_]u8{0} ** 128;
    std.mem.copyForwards(u8, bytes_extended[(128 - bytes.len)..128], bytes);

    const bytes_as_u1024: u1024 = std.mem.readInt(u1024, &bytes_extended, .big);
    var remaining = bytes_as_u1024;
    var i = out.len;
    while (remaining > 0) {
        if (i == 0) std.debug.panic("base58Encode: out is too small ({d} bytes) for the input {x}", .{ out.len, bytes_as_u1024 });
        i = i - 1;
        out[i] = alphabet[@intCast(remaining % 58)];
        remaining = remaining / 58;
    }
    i = i - 1;
    out[i] = alphabet[0];
    return i;
}

//#endregion

//#region BITCOIN #########################################################################

pub fn btcAddress(pubkey: CurvePoint, out: *const []u8, testnet: bool) usize {
    var serializedPoint: [33]u8 = undefined;
    serializePoint(pubkey, true, &serializedPoint);
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
    return base58Encode(&address, out.*);
}

pub const TxOutput = struct {
    amount: u64,
    script_pubkey: []u8,
};
pub const TxInput = struct {
    txid: u256,
    index: u32,
    script_sig: []u8,
    sequence: u64,
};
pub const Tx = struct {
    version: u32,
    inputs: []TxInput,
    outputs: []TxOutput,
    locktime: u32,
};

pub fn parseTx(data: []u8) !Tx {
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

    tx.locktime = cursor.readInt(u8);

    return tx;
}

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

        const PopError = error{ EmptyStack, Corrupted };
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

        const PopIntError = PopError || error{NotAnOperableInteger};
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
    };

    pub fn run(script: []const u8, stack: *Stack) error{ BadScript, VerifyFailed }!void {
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
                else => {
                    const msg = std.fmt.allocPrint(allocator, "Opcode {} not implemented\n", .{opcode}) catch @panic("While running a Script, a not implemented Opcode was found");
                    @panic(msg);
                },
            }
        }
    }

    pub fn validate(scriptSig: []const u8, scriptPubKey: []const u8) !bool {
        var stack = try Stack.init(scriptSig.len + scriptPubKey.len); // @TODO is this reasonable?
        defer stack.deinit();

        run(scriptSig, &stack) catch return false;
        run(scriptPubKey, &stack) catch return false;

        return stack.verify();
    }
};

//#endregion

//#region TESTS #########################################################################

const expect = std.testing.expect;

test "order of G is indeed n" {
    try expect(G.muli(secp256k1_n).atInfinity());
}

test "hash" {
    const hash_result = hashAsU256("The quick brown fox jumps over the lazy dog");
    try expect(hash_result == 0xd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592);
}

test "signing message" {
    const keys = generateKeyPair();
    const z = hashAsU256("my message");
    const signature: Signature = sign(z, keys.prvk);
    const valid = verify(z, keys.pubk, signature);
    try expect(valid);
}

test "sec serialization and parsing" {
    const p1 = G.muli(3858);

    var p1_uncompressed: [65]u8 = undefined;
    serializePoint(p1, false, &p1_uncompressed);
    const p1_uncompressed_parsed = parsePoint(p1_uncompressed[0..]);
    try expect(p1_uncompressed_parsed.eq(p1));

    var p1_compressed: [33]u8 = undefined;
    serializePoint(p1, true, &p1_compressed);
    const p1_compressed_parsed = parsePoint(p1_compressed[0..]);
    try expect(p1_compressed_parsed.eq(p1));
}

test "serialized signature" {
    const sig: Signature = .{
        .r = hashAsU256("idk"),
        .s = hashAsU256("anything"),
    };
    var serialized_sig: [72]u8 = undefined;
    serializeSignature(sig, &serialized_sig);
    const sig_parsed = parseSignature(&serialized_sig);
    try expect(sig_parsed.r == sig.r and sig_parsed.s == sig.s);
}

test "base58 encoding" {
    const u8_array = [8]u8{ 0x00, 0x00, 0x04, 0x09, 0x0a, 0x0f, 0x1a, 0xff };
    var encoded_u8_array: [10]u8 = undefined;
    const start = base58Encode(&u8_array, &encoded_u8_array);
    try expect(std.mem.eql(u8, encoded_u8_array[start..], "131Yr1PVY"));
}

test "btc address" {
    const prvk = 0x5da1cb5b4282e3f5c2314df81a3711fa7f0217401de5f72da0ab4906fab04f4c;
    const pubk = G.muli(prvk);
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
    const transaction = try parseTx(transaction_bytes[0..transaction_bytes.len]);
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
    try expect(try Script.validate(&script_sig, &script_pub_key));
}

//#endregion
