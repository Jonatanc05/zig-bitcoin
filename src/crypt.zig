const std = @import("std");
const FieldElementLib = @import("finite-field.zig");
const FieldElement = FieldElementLib.FieldElement;
const NumberType = FieldElementLib.NumberType;
const HalfNumberType = FieldElementLib.HalfNumberType;
const fe = FieldElementLib.fieldElementShortcut;
const CurvePoint = @import("elliptic-curve.zig").CurvePoint;
const secp256k1_a = 0;
const secp256k1_b = 7;
const secp256k1_Gx = 0x79be667e_f9dcbbac_55a06295_ce870b07_029bfcdb_2dce28d9_59f2815b_16f81798;
const secp256k1_Gy = 0x483ada77_26a3c465_5da4fbfc_0e1108a8_fd17b448_a6855419_9c47d08f_fb10d4b8;

pub const G = CurvePoint.init(
    FieldElement.init(secp256k1_Gx, secp256k1_p),
    FieldElement.init(secp256k1_Gy, secp256k1_p),
    FieldElement.init(secp256k1_a, secp256k1_p),
    FieldElement.init(secp256k1_b, secp256k1_p),
);

pub const secp256k1_p = 0xffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_fffffffe_fffffc2f;
pub const secp256k1_n = 0xffffffff_ffffffff_ffffffff_fffffffe_baaedce6_af48a03b_bfd25e8c_d0364141;

pub const Signature = struct {
    r: NumberType,
    s: NumberType,
};

pub fn hash(message: []const u8) HalfNumberType {
    const bytesInHalfNumberType: comptime_int = @divExact(@typeInfo(HalfNumberType).Int.bits, 8);
    var z_bytes: [bytesInHalfNumberType]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(message, z_bytes[0..bytesInHalfNumberType], .{});
    return std.mem.readInt(HalfNumberType, &z_bytes, std.builtin.Endian.little);
}

pub fn generateKeyPair() struct { pubk: CurvePoint, prvk: NumberType } {
    const e = @as(NumberType, std.crypto.random.int(HalfNumberType));
    const P = G.muli(e);
    return .{ .pubk = P, .prvk = e };
}

pub fn sign(z: NumberType, e: NumberType) Signature {
    const k = @as(NumberType, std.crypto.random.int(HalfNumberType));
    const r = G.muli(k).x.?.value;
    const k_inv = modpow(k, secp256k1_n - 2, secp256k1_n);
    const s = @mod(@mod((z + @mod(r * e, secp256k1_n)), secp256k1_n) * k_inv, secp256k1_n);
    return Signature{ .r = r, .s = s };
}

pub fn verify(z: NumberType, P: CurvePoint, sig: Signature) bool {
    const s_inv = modpow(sig.s, secp256k1_n - 2, secp256k1_n);
    const u = @mod(z * s_inv, secp256k1_n);
    const v = @mod(sig.r * s_inv, secp256k1_n);
    return G.muli(u).add(P.muli(v)).x.?.value == sig.r;
}

fn modpow(base: NumberType, exponent: NumberType, modulo: NumberType) NumberType {
    var base_mod = @mod(base, modulo);
    var result: NumberType = 1;
    var exp = exponent;
    while (exp > 0) {
        if (exp & 1 == 1) result = @mod((result * base_mod), modulo);
        base_mod = @mod((base_mod * base_mod), modulo);
        exp >>= 1;
    }
    return result;
}

// --------------- TESTS ---------------

const expect = std.testing.expect;

test "G is on curve" {
    FieldElementLib.setGlobalPrime(secp256k1_p);
    _ = CurvePoint.init(fe(secp256k1_Gx), fe(secp256k1_Gy), fe(secp256k1_a), fe(secp256k1_b));
}

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
