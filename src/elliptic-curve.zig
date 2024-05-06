const std = @import("std");
const FieldElementLib = @import("finite-field.zig");
const FieldElement = FieldElementLib.FieldElement;
const NumberType = FieldElementLib.NumberType;
const assert = std.debug.assert;

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

// --------------- TESTS ---------------

const expect = std.testing.expect;

const fe = FieldElementLib.fieldElementShortcut;

test "init points that should be on the curve" {
    FieldElementLib.setGlobalPrime(223);
    _ = CurvePoint.init(fe(192), fe(105), fe(0), fe(7));
    _ = CurvePoint.init(fe(17), fe(56), fe(0), fe(7));
    _ = CurvePoint.init(fe(1), fe(193), fe(0), fe(7));
}

test "point addition" {
    FieldElementLib.setGlobalPrime(223);
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
    FieldElementLib.setGlobalPrime(223);
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
