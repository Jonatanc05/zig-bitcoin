const std = @import("std");

pub const FieldElement = struct {
    value: i64,
    prime: i64,

    pub fn format(self: FieldElement, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("{}_F{}", .{ self.value, self.prime });
    }

    pub fn init(value: i64, prime: i64) FieldElement {
        std.debug.assert(value < prime and value >= 0);
        return FieldElement{ .value = value, .prime = prime };
    }

    pub fn eq(self: FieldElement, other: FieldElement) bool {
        return self.value == other.value and self.prime == other.prime;
    }

    pub fn add(self: FieldElement, other: FieldElement) FieldElement {
        std.debug.assert(self.prime == other.prime);
        return FieldElement.init(@mod((self.value + other.value), self.prime), self.prime);
    }

    pub fn sub(self: FieldElement, other: FieldElement) FieldElement {
        std.debug.assert(self.prime == other.prime);
        return FieldElement.init(@mod((self.value - other.value), self.prime), self.prime);
    }

    pub fn mul(self: FieldElement, other: FieldElement) FieldElement {
        std.debug.assert(self.prime == other.prime);
        return FieldElement.init(@mod((self.value * other.value), self.prime), self.prime);
    }

    pub fn pow(self: FieldElement, exponent: i64) FieldElement {
        var exp = @mod(exponent, self.prime - 1);
        var it: i64 = 1;
        const intResult = while (exp > 0) : (exp -= 1) {
            it = @mod(it * self.value, self.prime);
        } else it;
        return FieldElement.init(@mod(intResult, self.prime), self.prime);
    }

    pub fn div(self: FieldElement, other: FieldElement) FieldElement {
        std.debug.assert(self.prime == other.prime);
        return self.mul(other.pow(self.prime - 2));
    }
};

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

    const c = FieldElement.init(17, 31);
    try expect(c.pow(-3).eq(FieldElement.init(29, 31)));

    const d = FieldElement.init(4, 31);
    const e = FieldElement.init(11, 31);
    try expect(d.pow(-4).mul(e).eq(FieldElement.init(13, 31)));
}
