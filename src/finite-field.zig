const std = @import("std");
const assert = std.debug.assert;

pub const NumberType = u512;
pub const HalfNumberType = u256;
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
        return Self.init(@mod((self.value + other.value), self.prime), self.prime);
    }

    pub fn sub(self: Self, other: Self) Self {
        assert(self.prime == other.prime);
        if (self.value >= other.value) {
            return Self.init(@mod((self.value - other.value), self.prime), self.prime);
        } else {
            return Self.init(@mod((self.prime + self.value - other.value), self.prime), self.prime);
        }
    }

    pub fn mul(self: Self, other: Self) Self {
        assert(self.prime == other.prime);
        return Self.init(@mod((self.value * other.value), self.prime), self.prime);
    }
    pub fn muli(self: Self, otherRaw: NumberType) Self {
        return Self.init(@mod((self.value * otherRaw), self.prime), self.prime);
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

// --------------------- TESTS -------------------------------------

const expect = @import("std").testing.expect;

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
}
