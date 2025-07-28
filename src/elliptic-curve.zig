const std = @import("std");
const assert = std.debug.assert;
const expect = @import("std").testing.expect;

pub fn FieldElement(comptime NumberType: type) type {
    const SumExtendedNumberType = @Type(std.builtin.Type{ .int = .{ .signedness = .unsigned, .bits = @typeInfo(NumberType).int.bits + 1 } });
    const MulExtendedNumberType = @Type(std.builtin.Type{ .int = .{ .signedness = .unsigned, .bits = @typeInfo(NumberType).int.bits * 2 } });
    return struct {
        value: NumberType,
        prime: NumberType,

        const Self = @This();
        pub fn format(self: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;
            try writer.print("{}_F{}", .{ self.value, self.prime });
        }

        pub fn init(value: NumberType, prime: NumberType) Self {
            assert(value < prime and value >= 0);
            return Self{ .value = value, .prime = prime };
        }

        pub fn eq(self: Self, other: Self) bool {
            return self.value == other.value and self.prime == other.prime;
        }

        pub fn add(self: Self, other: Self) Self {
            assert(self.prime == other.prime);
            var res: SumExtendedNumberType = self.value;
            res = res + other.value;
            res = @mod(res, self.prime);
            return Self.init(@intCast(res), self.prime);
        }

        pub fn sub(self: Self, other: Self) Self {
            assert(self.prime == other.prime);
            if (self.value >= other.value) {
                return Self.init(@mod((self.value - other.value), self.prime), self.prime);
            } else {
                var res: SumExtendedNumberType = self.value;
                res = res + self.prime;
                res = res - other.value;
                res = @mod(res, self.prime);
                return Self.init(@intCast(res), self.prime);
            }
        }

        pub fn mul(self: Self, other: Self) Self {
            assert(self.prime == other.prime);
            var res: MulExtendedNumberType = self.value;
            res = res * other.value;
            res = @mod(res, self.prime);
            return Self.init(@intCast(res), self.prime);
        }
        pub fn muli(self: Self, otherRaw: NumberType) Self {
            var res: MulExtendedNumberType = self.value;
            res = res * otherRaw;
            res = @mod(res, self.prime);
            return Self.init(@intCast(res), self.prime);
        }

        pub fn pow(self: Self, exponent: NumberType) Self {
            var exp = exponent;
            var multiplier = self;
            var ret = Self.init(1, self.prime);
            while (exp > 0) : (exp >>= 1) {
                if (exp & 1 == 1)
                    ret = ret.mul(multiplier);
                multiplier = multiplier.mul(multiplier);
            }
            return ret;
        }

        pub fn div(self: Self, other: Self) Self {
            assert(self.prime == other.prime);
            return self.mul(other.inv());
        }

        pub fn inv(self: Self) Self {
            return self.pow(self.prime - 2);
        }

        var global_prime: NumberType = 1;
        pub fn setGlobalPrime(prime: NumberType) void {
            global_prime = prime;
        }
        pub fn fieldElementShortcut(value: NumberType) @This() {
            return @This().init(value, global_prime);
        }

        pub fn modpow(base: NumberType, exponent: NumberType, modulo: NumberType) NumberType {
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
    };
}

pub fn CurvePoint(comptime NumberType: type) type {
    const ElementType = FieldElement(NumberType);
    return struct {
        x: ?ElementType,
        y: ?ElementType,
        a: ElementType,
        b: ElementType,
        order: ?NumberType = null,

        pub fn format(self: @This(), comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;
            if (self.atInfinity()) {
                try writer.print("(inf, inf)", .{});
                return;
            }
            try writer.print("({x}, {x})", .{ self.x.?.value, self.y.?.value });
        }

        pub fn init(x: ?ElementType, y: ?ElementType, a: ElementType, b: ElementType) @This() {
            assert(a.prime == b.prime);
            if (x == null or y == null) {
                assert(x == null and y == null);
            } else {
                assert(x.?.prime == y.?.prime and y.?.prime == a.prime);

                // y^2 = x^3 + a * x + b
                assert(y.?.mul(y.?).eq(x.?.pow(3).add(a.mul(x.?)).add(b)));
            }

            return @This(){
                .x = x,
                .y = y,
                .a = a,
                .b = b,
            };
        }

        pub fn atInfinity(self: @This()) bool {
            if (self.x == null or self.y == null) {
                assert(self.x == null and self.y == null);
                return true;
            }
            return false;
        }

        pub fn eq(self: @This(), other: @This()) bool {
            assert(self.a.eq(other.a) or self.b.eq(other.b));
            if (self.atInfinity()) return other.atInfinity();
            return self.x.?.eq(other.x.?) and self.y.?.eq(other.y.?);
        }

        pub fn add(self: @This(), other: @This()) @This() {
            assert(self.a.eq(other.a) and self.b.eq(other.b));
            if (self.atInfinity()) return other;
            if (other.atInfinity()) return self;

            const x1 = self.x.?;
            const y1 = self.y.?;
            const x2 = other.x.?;
            const y2 = other.y.?;
            if (x1.eq(x2)) {
                if (y1.eq(y2)) {
                    if (y1.value == 0) return @This().init(null, null, self.a, self.b);
                    const s = x1.mul(x1).muli(3).add(self.a).div(y1.muli(2));
                    const x3 = s.mul(s).sub(x1).sub(x2);
                    const y3 = s.mul(x1.sub(x3)).sub(y1);
                    return @This().init(x3, y3, self.a, self.b);
                } else return @This().init(null, null, self.a, self.b);
            }

            const s = y2.sub(y1).div(x2.sub(x1));
            const x3 = s.mul(s).sub(x1).sub(x2);
            const y3 = s.mul(x1.sub(x3)).sub(y1);
            return @This().init(x3, y3, self.a, self.b);
        }

        pub fn muli(self: @This(), scalar: NumberType) @This() {
            if (self.atInfinity()) return @This().init(null, null, self.a, self.b);

            var result = @This().init(null, null, self.a, self.b);
            var adder = self;
            var scalarVar = if (self.order) |order| scalar % order else scalar;
            while (scalarVar != 0) : (scalarVar >>= 1) {
                if ((scalarVar & 1) != 0)
                    result = result.add(adder);
                adder = adder.add(adder);
            }
            return result;
        }
        pub fn mul(self: @This(), scalar: ElementType) @This() {
            return self.muli(scalar.value);
        }

        pub fn computeOrder(self: *@This()) void {
            var it = self.*;
            var i: NumberType = 1;
            self.order = while (true) : (i += 1) {
                it = it.add(self.*);
                if (it.atInfinity()) break i + 1;
            };
        }

        pub fn serialize(self: *const @This(), comptime compressed: bool, out: *[if (compressed) 33 else 65]u8) void {
            assert(self.x != null and self.y != null);
            var x_bytes: [32]u8 = undefined;
            std.mem.writeInt(u256, &x_bytes, self.x.?.value, .big);

            if (compressed) {
                assert(out.len >= 33);
                if (self.y.?.value % 2 == 0) {
                    out.* = [1]u8{0x02} ++ x_bytes;
                } else {
                    out.* = [1]u8{0x03} ++ x_bytes;
                }
            } else {
                assert(out.len >= 65);
                var y_bytes: [32]u8 = undefined;
                std.mem.writeInt(u256, &y_bytes, self.y.?.value, .big);
                out.* = [1]u8{0x04} ++ x_bytes ++ y_bytes;
            }
        }

        pub fn parse(bytes: []const u8, prime: NumberType, a: ElementType, b: ElementType) @This() {
            assert(bytes.len > 0);
            switch (bytes[0]) {
                0x02, 0x03 => {
                    assert(bytes.len == 33);
                    const x = ElementType.init(
                        std.mem.readInt(u256, bytes[1..33], .big),
                        prime,
                    );
                    const y_squared = x.pow(3).add(b);
                    const y = ElementType.modpow(y_squared.value, @divFloor(prime + 1, 4), prime);
                    const even_y = if (y % 2 == 0) ElementType.init(y, prime) else ElementType.init(prime - y, prime);
                    const odd_y = if (y % 2 == 1) ElementType.init(y, prime) else ElementType.init(prime - y, prime);
                    if (bytes[0] == 0x02) {
                        return @This().init(x, even_y, a, b);
                    } else if (bytes[0] == 0x03) {
                        return @This().init(x, odd_y, a, b);
                    } else unreachable;
                },
                0x04 => {
                    assert(bytes.len == 65);
                    const x = ElementType.init(std.mem.readInt(u256, bytes[1..33], .big), prime);
                    const y = ElementType.init(std.mem.readInt(u256, bytes[33..65], .big), prime);
                    return @This().init(x, y, a, b);
                },
                else => unreachable,
            }
        }
    };
}

//#region TESTS #########################################################################

const U256Element = FieldElement(u256);
const U256Point = CurvePoint(u256);
const fe = U256Element.fieldElementShortcut;

test "modulo addition" {
    const a = U256Element.init(2, 31);
    const b = U256Element.init(15, 31);
    const sum = a.add(b);
    try expect(sum.eq(U256Element.init(17, 31)));
    try expect(sum.eq(b.add(a)));

    const c = U256Element.init(17, 31);
    const d = U256Element.init(21, 31);
    const sum2 = c.add(d);
    try expect(sum2.eq(U256Element.init(7, 31)));
    try expect(sum2.eq(d.add(c)));
}

test "modulo sub" {
    const a = U256Element.init(29, 31);
    const b = U256Element.init(4, 31);
    try expect(a.sub(b).eq(U256Element.init(25, 31)));

    const c = U256Element.init(15, 31);
    const d = U256Element.init(30, 31);
    try expect(c.sub(d).eq(U256Element.init(16, 31)));

    const e = U256Element.init(17, 31);
    const f = U256Element.init(22, 31);
    try expect(e.sub(f).eq(U256Element.init(26, 31)));
}

test "modulo mul" {
    const a = U256Element.init(24, 31);
    const b = U256Element.init(19, 31);
    try expect(a.mul(b).eq(U256Element.init(22, 31)));
    try expect(b.mul(a).eq(U256Element.init(22, 31)));

    const c = U256Element.init(17, 31);
    const d = U256Element.init(21, 31);
    try expect(c.mul(d).eq(U256Element.init(16, 31)));
    try expect(d.mul(c).eq(U256Element.init(16, 31)));
}

test "modulo pow" {
    const a = U256Element.init(17, 31);
    try expect(a.pow(3).eq(U256Element.init(15, 31)));
    const b = U256Element.init(5, 31);
    const c = U256Element.init(18, 31);
    try expect(b.pow(5).mul(c).eq(U256Element.init(16, 31)));
}

test "modulo div" {
    const a = U256Element.init(3, 31);
    const b = U256Element.init(24, 31);
    try expect(a.div(b).eq(U256Element.init(4, 31)));
}

test "inv" {
    const a = U256Element.init(17, 31);
    try expect(a.inv().eq(U256Element.init(11, 31)));
    const b = U256Element.init(472, 587);
    try expect(b.inv().eq(U256Element.init(245, 587)));
    const c = U256Element.init(2358, 7919);
    try expect(c.inv().eq(U256Element.init(6532, 7919)));
    U256Element.setGlobalPrime(0xffffffff_ffffffff_ffffffff_fffffffe_baaedce6_af48a03b_bfd25e8c_d0364141);
    const d = fe(1234567890);
    try expect(d.inv().eq(fe(0x6bd555ecd0e4e06df23bfbb091158daaa0c6ba7347f32b95f4484e8dceb39d91)));
}

test "init points that should be on the curve" {
    U256Element.setGlobalPrime(223);
    _ = U256Point.init(fe(192), fe(105), fe(0), fe(7));
    _ = U256Point.init(fe(17), fe(56), fe(0), fe(7));
    _ = U256Point.init(fe(1), fe(193), fe(0), fe(7));
}

test "point addition" {
    U256Element.setGlobalPrime(223);
    const a = fe(0);
    const b = fe(7);
    const p1 = U256Point.init(fe(192), fe(105), a, b);
    const p2 = U256Point.init(fe(17), fe(56), a, b);
    try expect(p1.add(p2).eq(U256Point.init(fe(170), fe(142), a, b)));
    try expect(U256Point.init(fe(170), fe(142), a, b).add(U256Point.init(fe(60), fe(139), a, b)).eq(U256Point.init(fe(220), fe(181), a, b)));
    try expect(U256Point.init(fe(47), fe(71), a, b).add(U256Point.init(fe(17), fe(56), a, b)).eq(U256Point.init(fe(215), fe(68), a, b)));
    try expect(U256Point.init(fe(143), fe(98), a, b).add(U256Point.init(fe(76), fe(66), a, b)).eq(U256Point.init(fe(47), fe(71), a, b)));
}

test "scalar multiplication" {
    U256Element.setGlobalPrime(223);
    const a = fe(0);
    const b = fe(7);
    const p1 = U256Point.init(fe(192), fe(105), a, b);
    const p2 = U256Point.init(fe(143), fe(98), a, b);
    const p3 = U256Point.init(fe(47), fe(71), a, b);
    try expect(p1.muli(2).eq(p1.add(p1)));
    try expect(p1.muli(2).eq(U256Point.init(fe(49), fe(71), a, b)));
    try expect(p2.muli(2).eq(U256Point.init(fe(64), fe(168), a, b)));
    try expect(p3.muli(2).eq(U256Point.init(fe(36), fe(111), a, b)));
    try expect(p3.muli(4).eq(U256Point.init(fe(194), fe(51), a, b)));
    try expect(p3.muli(8).eq(U256Point.init(fe(116), fe(55), a, b)));
    try expect(p3.muli(21).atInfinity());
}

test "sec serialization and parsing" {
    const secp256k1_p = 0xffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_fffffffe_fffffc2f;
    U256Element.setGlobalPrime(secp256k1_p);
    const p1 = U256Point.init(
        fe(0x8b1d28e29c07f93e00531b199c5db7e053a8be9507c35a8b0b4a3536192a281e),
        fe(0x1fdd88952ef28c81369cf00a7204d9d08cf58d38c0f97ec124a893b8c98d3516),
        fe(0),
        fe(7),
    );

    var p1_uncompressed: [65]u8 = undefined;
    p1.serialize(false, &p1_uncompressed);
    const p1_uncompressed_parsed = U256Point.parse(
        p1_uncompressed[0..],
        secp256k1_p,
        fe(0),
        fe(7),
    );
    try expect(p1_uncompressed_parsed.eq(p1));

    var p1_compressed: [33]u8 = undefined;
    p1.serialize(true, &p1_compressed);
    const p1_compressed_parsed = U256Point.parse(
        p1_compressed[0..],
        secp256k1_p,
        fe(0),
        fe(7),
    );
    try expect(p1_compressed_parsed.eq(p1));
}

//#endregion
