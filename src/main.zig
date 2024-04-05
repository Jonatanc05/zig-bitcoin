const std = @import("std");

const FiniteFieldError = error{ FieldMismatch, InvalidField };
const FieldElement = struct {
    value: i64,
    prime: i64,

    pub fn init(value: i64, prime: i64) !FieldElement {
        if (value >= prime or value < 0)
            return FiniteFieldError.InvalidField;
        return FieldElement{ .value = value, .prime = prime };
    }

    pub fn eq(self: FieldElement, other: FieldElement) bool {
        return self.value == other.value and self.prime == other.prime;
    }

    pub fn add(self: FieldElement, other: FieldElement) !FieldElement {
        if (self.prime != other.prime)
            return FiniteFieldError.FieldMismatch;
        return FieldElement.init(@mod((self.value + other.value), self.prime), self.prime);
    }

    pub fn sub(self: FieldElement, other: FieldElement) !FieldElement {
        if (self.prime != other.prime)
            return FiniteFieldError.FieldMismatch;

        return FieldElement.init(@mod((self.value - other.value), self.prime), self.prime);
    }

    pub fn mul(self: FieldElement, other: FieldElement) !FieldElement {
        if (self.prime != other.prime) {
            return FiniteFieldError.FieldMismatch;
        }
        return FieldElement.init(@mod((self.value * other.value), self.prime), self.prime);
    }

    pub fn pow(self: FieldElement, exponent: i64) !FieldElement {
        var exp = @mod(exponent, self.prime - 1);
        var it: i64 = 1;
        const intResult = while (exp > 0) : (exp -= 1) {
            it = @mod(it * self.value, self.prime);
        } else it;
        return FieldElement.init(@mod(intResult, self.prime), self.prime);
    }

    pub fn div(self: FieldElement, other: FieldElement) !FieldElement {
        if (self.prime != other.prime) {
            return FiniteFieldError.FieldMismatch;
        }

        return try self.mul(try other.pow(self.prime - 2));
    }
};

pub fn main() !void {
    const a = try FieldElement.init(10, 13);
    const b = try FieldElement.init(5, 13);
    std.debug.print("Element a: {}\n", .{a});
    std.debug.print("Element b: {}\n", .{b});
    std.debug.print("a + b: {}\n", .{try a.add(b)});
    std.debug.print("a - b: {}\n", .{try a.sub(b)});
    std.debug.print("b - a: {}\n", .{try b.sub(a)});
    std.debug.print("a * b: {}\n", .{try a.mul(b)});
    std.debug.print("a ** 2: {}\n", .{try a.pow(2)});
    std.debug.print("a / b: {}\n", .{try a.div(b)});
}

// --------------------- TESTS -------------------------------------

const expect = std.testing.expect;

test "init invalid FieldElement" {
    _ = FieldElement.init(18, 11) catch |err| {
        try expect(err == error.InvalidField);

        _ = FieldElement.init(-3, 13) catch |err2| {
            try expect(err2 == error.InvalidField);
            return;
        };

        unreachable;
    };
    unreachable;
}

test "modulo addition" {
    const a = try FieldElement.init(2, 31);
    const b = try FieldElement.init(15, 31);
    const sum = try a.add(b);
    try expect(sum.eq(try FieldElement.init(17, 31)));
    try expect(sum.eq(try b.add(a)));

    const c = try FieldElement.init(17, 31);
    const d = try FieldElement.init(21, 31);
    const sum2 = try c.add(d);
    try expect(sum2.eq(try FieldElement.init(7, 31)));
    try expect(sum2.eq(try d.add(c)));
}

test "modulo sub" {
    const a = try FieldElement.init(29, 31);
    const b = try FieldElement.init(4, 31);
    try expect((try a.sub(b)).eq(try FieldElement.init(25, 31)));

    const c = try FieldElement.init(15, 31);
    const d = try FieldElement.init(30, 31);
    try expect((try c.sub(d)).eq(try FieldElement.init(16, 31)));

    const e = try FieldElement.init(17, 31);
    const f = try FieldElement.init(22, 31);
    try expect((try e.sub(f)).eq(try FieldElement.init(26, 31)));
}

test "modulo mul" {
    const a = try FieldElement.init(24, 31);
    const b = try FieldElement.init(19, 31);
    try expect((try a.mul(b)).eq(try FieldElement.init(22, 31)));
    try expect((try b.mul(a)).eq(try FieldElement.init(22, 31)));

    const c = try FieldElement.init(17, 31);
    const d = try FieldElement.init(21, 31);
    try expect((try c.mul(d)).eq(try FieldElement.init(16, 31)));
    try expect((try d.mul(c)).eq(try FieldElement.init(16, 31)));
}

test "modulo pow" {
    const a = try FieldElement.init(17, 31);
    try expect((try a.pow(3)).eq(try FieldElement.init(15, 31)));
    const b = try FieldElement.init(5, 31);
    const c = try FieldElement.init(18, 31);
    try expect((try (try b.pow(5)).mul(c)).eq(try FieldElement.init(16, 31)));
}

test "modulo div" {
    const a = try FieldElement.init(3, 31);
    const b = try FieldElement.init(24, 31);
    try expect((try a.div(b)).eq(try FieldElement.init(4, 31)));

    const c = try FieldElement.init(17, 31);
    try expect((try c.pow(-3)).eq(try FieldElement.init(29, 31)));

    const d = try FieldElement.init(4, 31);
    const e = try FieldElement.init(11, 31);
    try expect((try (try d.pow(-4)).mul(e)).eq(try FieldElement.init(13, 31)));
}
