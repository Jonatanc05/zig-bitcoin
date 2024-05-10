const c_ripemd = @cImport({
    @cInclude("ripemd.c");
});
const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const FieldElementLib = @import("finite-field.zig");
const FieldElement = FieldElementLib.FieldElement;
const NumberType = FieldElementLib.NumberType;
const MulExtendedNumberType = FieldElementLib.MulExtendedNumberType;
const fe = FieldElementLib.fieldElementShortcut;
const CurvePoint = @import("elliptic-curve.zig").CurvePoint;
const assert = std.debug.assert;
const native_endian = @import("builtin").target.cpu.arch.endian();

comptime {
    if (NumberType != u256) {
        // This is because we use secp256k1
        @compileError("Only NumberType = u256 is supported");
    }
}

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
    r: NumberType,
    s: NumberType,
};

pub fn hash(message: []const u8) NumberType {
    const bytesInNumberType = @divExact(@typeInfo(NumberType).Int.bits, 8);
    var z_bytes: [bytesInNumberType]u8 = undefined;
    Sha256.hash(message, z_bytes[0..bytesInNumberType], .{});
    return std.mem.readInt(NumberType, &z_bytes, native_endian);
}

pub fn generateKeyPair() struct { pubk: CurvePoint, prvk: NumberType } {
    const e = std.crypto.random.int(NumberType);
    const P = G.muli(e);
    return .{ .pubk = P, .prvk = e };
}

pub fn sign(z: NumberType, e: NumberType) Signature {
    const k = std.crypto.random.int(NumberType);
    const r = G.muli(k).x.?.value;
    const k_inv = modpow(k, secp256k1_n - 2, secp256k1_n);
    const s: NumberType = s_calc: { // s = (r * e + z) * k_inv (mod n)
        var temp: MulExtendedNumberType = r;
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

pub fn verify(z: NumberType, P: CurvePoint, sig: Signature) bool {
    const s_inv = modpow(sig.s, secp256k1_n - 2, secp256k1_n);

    const u: NumberType = u_calc: { // u = z * s_inv (mod n)
        var temp: MulExtendedNumberType = z;
        temp = temp * s_inv;
        temp = @mod(temp, secp256k1_n);
        break :u_calc @intCast(temp);
    };

    const v: NumberType = v_calc: { // v = r * s_inv (mod n)
        var temp: MulExtendedNumberType = sig.r;
        temp = temp * s_inv;
        temp = @mod(temp, secp256k1_n);
        break :v_calc @intCast(temp);
    };

    return G.muli(u).add(P.muli(v)).x.?.value == sig.r;
}

fn bytesNeeded(comptime T: type, compressed: bool) comptime_int {
    const bytes_in_type = @divExact(@typeInfo(T).Int.bits, 8);
    if (compressed) {
        return bytes_in_type + 1;
    } else {
        return 2 * bytes_in_type + 1;
    }
}
pub fn serializePoint(point: CurvePoint, comptime compressed: bool, out: *[bytesNeeded(NumberType, compressed)]u8) void {
    assert(point.x != null and point.y != null); // @TODO infinity
    assert(point.x.?.prime == secp256k1_p);
    const bytes_in_number_type = @divExact(@typeInfo(NumberType).Int.bits, 8);
    var x_bytes: [bytes_in_number_type]u8 = undefined;
    std.mem.writeInt(NumberType, &x_bytes, point.x.?.value, .big);

    if (compressed) {
        assert(out.len >= bytes_in_number_type + 1);
        if (point.y.?.value % 2 == 0) {
            out.* = [1]u8{0x02} ++ x_bytes;
        } else {
            out.* = [1]u8{0x03} ++ x_bytes;
        }
    } else {
        assert(out.len >= 2 * bytes_in_number_type + 1);
        var y_bytes: [bytes_in_number_type]u8 = undefined;
        std.mem.writeInt(NumberType, &y_bytes, point.y.?.value, .big);
        out.* = [1]u8{0x04} ++ x_bytes ++ y_bytes;
    }
}

pub fn parsePoint(bytes: []const u8) CurvePoint {
    assert(bytes.len > 0);
    switch (bytes[0]) {
        0x02, 0x03 => {
            assert(bytes.len == 33);
            const x = FieldElement.init(
                std.mem.readInt(NumberType, bytes[1..33], .big),
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
            const x = FieldElement.init(std.mem.readInt(NumberType, bytes[1..33], .big), secp256k1_p);
            const y = FieldElement.init(std.mem.readInt(NumberType, bytes[33..65], .big), secp256k1_p);
            return CurvePoint.init(x, y, secp256k1_a_fe, secp256k1_b_fe);
        },
        else => unreachable,
    }
}

pub fn serializeSignature(sig: Signature, out: *[72]u8) void {
    const bytes_0_to_5 = [_]u8{ 0x30, 0x46, 0x02, 0x21, 0x00 };
    std.mem.copyForwards(u8, out[0..5], &bytes_0_to_5);
    std.mem.writeInt(NumberType, out[5..37], sig.r, .big);
    const bytes_37_to_39 = [_]u8{ 0x02, 0x21 };
    std.mem.copyForwards(u8, out[37..39], &bytes_37_to_39);
    std.mem.writeInt(NumberType, out[39..71], sig.s, .big);
}

pub fn parseSignature(bytes: []const u8) Signature {
    assert(bytes.len == 72);
    assert(bytes[0] == 0x30 and bytes[1] == 0x46);
    return .{
        .r = std.mem.readInt(NumberType, bytes[5..37], .big),
        .s = std.mem.readInt(NumberType, bytes[39..71], .big),
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

fn modpow(base: NumberType, exponent: NumberType, modulo: NumberType) NumberType {
    var base_mod = @mod(base, modulo);
    var result: MulExtendedNumberType = 1;
    var exp = exponent;
    while (exp > 0) {
        if (exp & 1 == 1) {
            result = result * base_mod;
            result = @mod(result, modulo);
        }
        var base_mod_temp: MulExtendedNumberType = base_mod;
        base_mod_temp = base_mod_temp * base_mod_temp;
        base_mod_temp = @mod(base_mod_temp, modulo);
        base_mod = @mod(@as(NumberType, @intCast(base_mod_temp)), modulo);
        exp >>= 1;
    }
    return @intCast(result);
}

// --------------- TESTS ---------------

const expect = std.testing.expect;

test "order of G is indeed n" {
    try expect(G.muli(secp256k1_n).atInfinity());
}

test "signing message" {
    const keys = generateKeyPair();
    const z = hash("my message");
    const signature: Signature = sign(z, keys.prvk);
    const valid = verify(z, keys.pubk, signature);
    try expect(valid);
}

test "sec serialization and parsing" {
    const p1 = G.muli(3858);

    var p1_uncompressed: [1 + 2 * @divExact(@typeInfo(NumberType).Int.bits, 8)]u8 = undefined;
    serializePoint(p1, false, &p1_uncompressed);
    const p1_uncompressed_parsed = parsePoint(p1_uncompressed[0..]);
    try expect(p1_uncompressed_parsed.eq(p1));

    var p1_compressed: [1 + @divExact(@typeInfo(NumberType).Int.bits, 8)]u8 = undefined;
    serializePoint(p1, true, &p1_compressed);
    const p1_compressed_parsed = parsePoint(p1_compressed[0..]);
    try expect(p1_compressed_parsed.eq(p1));
}

test "serialized signature" {
    const sig: Signature = .{
        .r = hash("idk"),
        .s = hash("anything"),
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
