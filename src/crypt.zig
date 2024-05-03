const std = @import("std");
const FieldElementLib = @import("finite-field.zig");
const FieldElement = FieldElementLib.FieldElement;
const NumberType = FieldElementLib.NumberType;
const MulExtendedNumberType = FieldElementLib.MulExtendedNumberType;
const fe = FieldElementLib.fieldElementShortcut;
const CurvePoint = @import("elliptic-curve.zig").CurvePoint;
const native_endian = @import("builtin").target.cpu.arch.endian();

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

pub fn hash(message: []const u8) NumberType {
    const bytesInNumberType: comptime_int = @divExact(@typeInfo(NumberType).Int.bits, 8);
    var z_bytes: [bytesInNumberType]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(message, z_bytes[0..bytesInNumberType], .{});
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
