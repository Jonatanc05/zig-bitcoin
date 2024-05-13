const std = @import("std");
const assert = std.debug.assert;
const expect = @import("std").testing.expect;

//#region FINITE_FIELD #########################################################################

pub const NumberType = u256;
pub const SumExtendedNumberType = u257;
pub const MulExtendedNumberType = u512;
pub const FieldElement = struct {
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
};

var global_prime: NumberType = 1;
pub fn setGlobalPrime(prime: NumberType) void {
    global_prime = prime;
}
pub fn fieldElementShortcut(value: NumberType) FieldElement {
    return FieldElement.init(value, global_prime);
}

//#endregion

//#region ELLIPTIC_CURVE #########################################################################

pub const CurvePoint = struct {
    x: ?FieldElement,
    y: ?FieldElement,
    a: FieldElement,
    b: FieldElement,
    order: ?NumberType = null,

    pub fn format(self: CurvePoint, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        if (self.atInfinity()) {
            try writer.print("(inf, inf)", .{});
            return;
        }
        try writer.print("({x}, {x})", .{ self.x.?.value, self.y.?.value });
    }

    pub fn init(x: ?FieldElement, y: ?FieldElement, a: FieldElement, b: FieldElement) CurvePoint {
        assert(a.prime == b.prime);
        if (x == null or y == null) {
            assert(x == null and y == null);
        } else {
            assert(x.?.prime == y.?.prime and y.?.prime == a.prime);

            // y^2 = x^3 + a * x + b
            assert(y.?.mul(y.?).eq(x.?.pow(3).add(a.mul(x.?)).add(b)));
        }

        return CurvePoint{
            .x = x,
            .y = y,
            .a = a,
            .b = b,
        };
    }

    pub fn atInfinity(self: CurvePoint) bool {
        if (self.x == null or self.y == null) {
            assert(self.x == null and self.y == null);
            return true;
        }
        return false;
    }

    pub fn eq(self: CurvePoint, other: CurvePoint) bool {
        assert(self.a.eq(other.a) or self.b.eq(other.b));
        if (self.atInfinity()) return other.atInfinity();
        return self.x.?.eq(other.x.?) and self.y.?.eq(other.y.?);
    }

    pub fn add(self: CurvePoint, other: CurvePoint) CurvePoint {
        assert(self.a.eq(other.a) and self.b.eq(other.b));
        if (self.atInfinity()) return other;
        if (other.atInfinity()) return self;

        const x1 = self.x.?;
        const y1 = self.y.?;
        const x2 = other.x.?;
        const y2 = other.y.?;
        if (x1.eq(x2)) {
            if (y1.eq(y2)) {
                if (y1.value == 0) return CurvePoint.init(null, null, self.a, self.b);
                const s = x1.mul(x1).muli(3).add(self.a).div(y1.muli(2));
                const x3 = s.mul(s).sub(x1).sub(x2);
                const y3 = s.mul(x1.sub(x3)).sub(y1);
                return CurvePoint.init(x3, y3, self.a, self.b);
            } else return CurvePoint.init(null, null, self.a, self.b);
        }

        const s = y2.sub(y1).div(x2.sub(x1));
        const x3 = s.mul(s).sub(x1).sub(x2);
        const y3 = s.mul(x1.sub(x3)).sub(y1);
        return CurvePoint.init(x3, y3, self.a, self.b);
    }

    pub fn muli(self: CurvePoint, scalar: NumberType) CurvePoint {
        if (self.atInfinity()) return CurvePoint.init(null, null, self.a, self.b);

        var result = CurvePoint.init(null, null, self.a, self.b);
        var adder = self;
        var scalarVar = if (self.order != null) scalar % self.order.? else scalar;
        while (scalarVar != 0) : (scalarVar >>= 1) {
            if ((scalarVar & 1) != 0)
                result = result.add(adder);
            adder = adder.add(adder);
        }
        return result;
    }
    pub fn mul(self: CurvePoint, scalar: FieldElement) CurvePoint {
        return self.muli(scalar.value);
    }

    pub fn computeOrder(self: *CurvePoint) void {
        var it = self.*;
        var i: NumberType = 1;
        self.order = while (true) : (i += 1) {
            it = it.add(self.*);
            if (it.atInfinity()) break i + 1;
        };
    }
};

//#endregion

//#region TESTS #########################################################################

test "modulo addition" {
    const a = FieldElement.init(2, 31);
    const b = FieldElement.init(15, 31);
    const sum = a.add(b);
    try expect(sum.eq(FieldElement.init(17, 31)));
    try expect(sum.eq(b.add(a)));

    const c = FieldElement.init(17, 31);
    const d = FieldElement.init(21, 31);
    const sum2 = c.add(d);
    try expect(sum2.eq(FieldElement.init(7, 31)));
    try expect(sum2.eq(d.add(c)));
}

test "modulo sub" {
    const a = FieldElement.init(29, 31);
    const b = FieldElement.init(4, 31);
    try expect(a.sub(b).eq(FieldElement.init(25, 31)));

    const c = FieldElement.init(15, 31);
    const d = FieldElement.init(30, 31);
    try expect(c.sub(d).eq(FieldElement.init(16, 31)));

    const e = FieldElement.init(17, 31);
    const f = FieldElement.init(22, 31);
    try expect(e.sub(f).eq(FieldElement.init(26, 31)));
}

test "modulo mul" {
    const a = FieldElement.init(24, 31);
    const b = FieldElement.init(19, 31);
    try expect(a.mul(b).eq(FieldElement.init(22, 31)));
    try expect(b.mul(a).eq(FieldElement.init(22, 31)));

    const c = FieldElement.init(17, 31);
    const d = FieldElement.init(21, 31);
    try expect(c.mul(d).eq(FieldElement.init(16, 31)));
    try expect(d.mul(c).eq(FieldElement.init(16, 31)));
}

test "modulo pow" {
    const a = FieldElement.init(17, 31);
    try expect(a.pow(3).eq(FieldElement.init(15, 31)));
    const b = FieldElement.init(5, 31);
    const c = FieldElement.init(18, 31);
    try expect(b.pow(5).mul(c).eq(FieldElement.init(16, 31)));
}

test "modulo div" {
    const a = FieldElement.init(3, 31);
    const b = FieldElement.init(24, 31);
    try expect(a.div(b).eq(FieldElement.init(4, 31)));
}

test "inv" {
    const a = FieldElement.init(17, 31);
    try expect(a.inv().eq(FieldElement.init(11, 31)));
    const b = FieldElement.init(472, 587);
    try expect(b.inv().eq(FieldElement.init(245, 587)));
    const c = FieldElement.init(2358, 7919);
    try expect(c.inv().eq(FieldElement.init(6532, 7919)));
    setGlobalPrime(0xffffffff_ffffffff_ffffffff_fffffffe_baaedce6_af48a03b_bfd25e8c_d0364141);
    const d = fieldElementShortcut(1234567890);
    try expect(d.inv().eq(fieldElementShortcut(0x6bd555ecd0e4e06df23bfbb091158daaa0c6ba7347f32b95f4484e8dceb39d91)));
}

const fe = fieldElementShortcut;

test "init points that should be on the curve" {
    setGlobalPrime(223);
    _ = CurvePoint.init(fe(192), fe(105), fe(0), fe(7));
    _ = CurvePoint.init(fe(17), fe(56), fe(0), fe(7));
    _ = CurvePoint.init(fe(1), fe(193), fe(0), fe(7));
}

test "point addition" {
    setGlobalPrime(223);
    const a = fe(0);
    const b = fe(7);
    const p1 = CurvePoint.init(fe(192), fe(105), a, b);
    const p2 = CurvePoint.init(fe(17), fe(56), a, b);
    try expect(p1.add(p2).eq(CurvePoint.init(fe(170), fe(142), a, b)));
    try expect(CurvePoint.init(fe(170), fe(142), a, b).add(CurvePoint.init(fe(60), fe(139), a, b)).eq(CurvePoint.init(fe(220), fe(181), a, b)));
    try expect(CurvePoint.init(fe(47), fe(71), a, b).add(CurvePoint.init(fe(17), fe(56), a, b)).eq(CurvePoint.init(fe(215), fe(68), a, b)));
    try expect(CurvePoint.init(fe(143), fe(98), a, b).add(CurvePoint.init(fe(76), fe(66), a, b)).eq(CurvePoint.init(fe(47), fe(71), a, b)));
}

test "scalar multiplication" {
    setGlobalPrime(223);
    const a = fe(0);
    const b = fe(7);
    const p1 = CurvePoint.init(fe(192), fe(105), a, b);
    const p2 = CurvePoint.init(fe(143), fe(98), a, b);
    const p3 = CurvePoint.init(fe(47), fe(71), a, b);
    try expect(p1.muli(2).eq(p1.add(p1)));
    try expect(p1.muli(2).eq(CurvePoint.init(fe(49), fe(71), a, b)));
    try expect(p2.muli(2).eq(CurvePoint.init(fe(64), fe(168), a, b)));
    try expect(p3.muli(2).eq(CurvePoint.init(fe(36), fe(111), a, b)));
    try expect(p3.muli(4).eq(CurvePoint.init(fe(194), fe(51), a, b)));
    try expect(p3.muli(8).eq(CurvePoint.init(fe(116), fe(55), a, b)));
    try expect(p3.muli(21).atInfinity());
}

//#endregion
