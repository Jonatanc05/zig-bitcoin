const std = @import("std");
const inf = std.math.inf(f64);

pub const CurvePoint = struct {
    x: f64,
    y: f64,
    a: f64,
    b: f64,

    pub fn format(self: CurvePoint, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("({}, {})", .{ self.x, self.y });
    }

    pub fn init(x: f64, y: f64, a: f64, b: f64) CurvePoint {
        if (x == inf or y == inf) {
            std.debug.assert(x == y);
            return CurvePoint{
                .x = x,
                .y = y,
                .a = a,
                .b = b,
            };
        }

        std.debug.assert(y * y == x * x * x + a * x + b);
        return CurvePoint{
            .x = x,
            .y = y,
            .a = a,
            .b = b,
        };
    }

    pub fn atInfinity(self: CurvePoint) bool {
        const atInf: bool = (self.x == inf or self.y == inf);
        if (atInf) std.debug.assert(self.x == self.y);
        return atInf;
    }

    pub fn eq(self: CurvePoint, other: CurvePoint) bool {
        std.debug.assert(self.a == other.a or self.b == other.b);
        return self.x == other.x and self.y == other.y;
    }

    pub fn add(self: CurvePoint, other: CurvePoint) CurvePoint {
        std.debug.assert(self.a == other.a and self.b == other.b);

        if (self.atInfinity()) return other;
        if (other.atInfinity()) return self;

        if (self.x == other.x) {
            if (self.y == other.y) {
                if (self.y == 0) return CurvePoint.init(inf, inf, self.a, self.b);
                const s = (3 * self.x * self.x + self.a) / (2 * self.y);
                const x = s * s - self.x - other.x;
                const y = s * (x - self.x) + self.y;
                return CurvePoint.init(x, y, self.a, self.b);
            } else if (self.y == -other.y) {
                return CurvePoint.init(inf, inf, self.a, self.b);
            } else unreachable;
        }

        const s = (other.y - self.y) / (other.x - self.x);
        const x = s * s - self.x - other.x;
        const y = s * (x - self.x) + self.y;
        return CurvePoint.init(x, y, self.a, self.b);
    }
};

// --------------------- TESTS -------------------------------------

const expect = @import("std").testing.expect;

test "point at infinity" {
    const I = CurvePoint.init(inf, inf, 5, 7);
    try expect(I.x == inf);
    try expect(I.y == inf);
}

test "point at inf sum (invertibility)" {
    const p1 = CurvePoint.init(-1, -1, 5, 7);
    const p2 = CurvePoint.init(-1, 1, 5, 7);
    const I = CurvePoint.init(inf, inf, 5, 7);
    try expect(p1.add(I).eq(p1));
    try expect(I.add(p2).eq(CurvePoint.init(-1, 1, 5, 7)));
    try expect(p1.add(p2).eq(CurvePoint.init(inf, inf, 5, 7)));
}

test "sum" {
    const a = CurvePoint.init(2, 5, 5, 7);
    const b = CurvePoint.init(-1, -1, 5, 7);
    try expect(a.add(b).eq(CurvePoint.init(3, 7, 5, 7)));
}

test "sum equal points" {
    const a = CurvePoint.init(-1, -1, 5, 7);
    const b = CurvePoint.init(-1, -1, 5, 7);
    try expect(a.add(b).eq(CurvePoint.init(18, -77, 5, 7)));
}

test "sum equal points at y=0" {
    const a = CurvePoint.init(0, 0, 5, 0);
    const b = CurvePoint.init(0, 0, 5, 0);
    try expect(a.add(b).eq(CurvePoint.init(inf, inf, 5, 7)));
}
