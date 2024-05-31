// std
const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

// managed dependencies
const Cursor = @import("cursor.zig").Cursor;
const EllipticCurveLib = @import("elliptic-curve.zig");
const FieldElement = EllipticCurveLib.FieldElement(u256);
const CurvePoint = EllipticCurveLib.CurvePoint(u256);

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

    pub fn serialize(self: *const Signature, out: *[72]u8) void {
        const bytes_0_to_5 = [_]u8{ 0x30, 0x46, 0x02, 0x21, 0x00 };
        std.mem.copyForwards(u8, out[0..5], &bytes_0_to_5);
        std.mem.writeInt(u256, out[5..37], self.r, .big);
        const bytes_37_to_39 = [_]u8{ 0x02, 0x21 };
        std.mem.copyForwards(u8, out[37..39], &bytes_37_to_39);
        std.mem.writeInt(u256, out[39..71], self.s, .big);
    }

    pub fn parse(bytes: []const u8) Signature {
        assert(bytes.len == 72);
        assert(bytes[0] == 0x30 and bytes[1] == 0x46);
        return .{
            .r = std.mem.readInt(u256, bytes[5..37], .big),
            .s = std.mem.readInt(u256, bytes[39..71], .big),
        };
    }
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
    const k_inv = FieldElement.modpow(k, secp256k1_n - 2, secp256k1_n);
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
    const s_inv = FieldElement.modpow(sig.s, secp256k1_n - 2, secp256k1_n);

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

test "serialized signature" {
    const sig: Signature = .{
        .r = hashAsU256("idk"),
        .s = hashAsU256("anything"),
    };
    var serialized_sig: [72]u8 = undefined;
    sig.serialize(&serialized_sig);
    const sig_parsed = Signature.parse(&serialized_sig);
    try expect(sig_parsed.r == sig.r and sig_parsed.s == sig.s);
}

//#endregion
