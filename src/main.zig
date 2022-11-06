const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const network = @import("network");
const builtin = @import("builtin");

const StrList = std.ArrayList([]const u8);
const QuestionList = std.ArrayList(Question);

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();
    try network.init();
    defer network.deinit();
    std.log.info("All your codebase are belong to us.", .{});
    const sock = try network.connectToHost(allocator, "192.168.0.23", 53, .udp);
    defer sock.close();
    const writer = sock.writer();

    const header = Header{
        .id = 1,
        .response = false,
        .opcode = .query,
        .authoritative_answer = false,
        .truncation = false,
        .recursion_desired = true,
        .recursion_available = false,
        .z = 0,
        .response_code = .no_error,
        .question_count = 1,
        .answer_count = 0,
        .name_server_count = 0,
        .additional_record_count = 0,
    };

    const domain = try DomainName.from_string(allocator, "lambda.cx");
    defer domain.deinit();
    const question = Question{
        .qname = domain,
        .qtype = @intToEnum(QType, @enumToInt(Type.A)),
        .qclass = @intToEnum(QClass, @enumToInt(Class.IN)),
    };
    const questions = [_]Question{ question };
    const message = Message{
        .allocator = allocator,
        .header = header,
        .questions = &questions,
        .answers = &.{},
        .authorities = &.{},
        .additional = &.{}
    };
    var message_bytes = std.ArrayList(u8).init(allocator);
    defer message_bytes.deinit();
    try message.to_writer(message_bytes.writer());

    std.debug.print("Sending bytes: {any}\n", .{ message_bytes.items });
    try writer.writeAll(message_bytes.items);
    var recv = [_]u8{0} ** 1024;
    const recv_size = try sock.receive(&recv);
    std.debug.print("Recv: {any}\n", .{ recv[0..recv_size] });
    var recv_buffer = std.io.fixedBufferStream(recv[0..recv_size]);
    const response = try Message.from_reader(allocator, recv_buffer.reader());
    defer response.deinit();
    std.debug.print("{any}\n", .{ response });
}

pub const Message = struct {
    allocator: mem.Allocator,
    header: Header,
    questions: []const Question,
    answers: []const ResourceRecord,
    authorities: []const ResourceRecord,
    additional: []const ResourceRecord,

    pub fn to_writer(self: *const Message, writer: anytype) !void {
        try writer.writeAll(&self.header.to_bytes());
        for (self.questions) |question| {
            try question.to_writer(writer);
        }
    }

    pub fn from_reader(allocator: mem.Allocator, reader: anytype) !Message {
        var questions = QuestionList.init(allocator);
        var header = try Header.from_reader(reader);
        var qidx: usize = 0;
        while (qidx < header.question_count) : (qidx += 1) {
            const question = try Question.from_reader(allocator, reader);
            try questions.append(question);
        }

        return Message{
            .allocator = allocator,
            .header = header,
            .questions = questions.toOwnedSlice(),
            .answers = &.{},
            .authorities = &.{},
            .additional = &.{},
        };
    }

    pub fn deinit(self: *const Message) void {
        for (self.questions) |question| {
            question.deinit();
        }
        self.allocator.free(self.questions);
    }
};

pub const Header = packed struct (u96) {
    /// An identifier assigned by the program that generates any kind
    /// of query. This identifier is copied the corresponding reply
    /// and can be used by the requester to match up replies to
    /// outstanding queries.
    id: u16,

    // Flags section. Fields are ordered this way because zig has
    // little endian bit order for bit fields.

    // Byte one

    /// Directs the name server to pursue the query recursively.
    /// Recursive query support is optional.
    recursion_desired: bool,
    /// If the message was truncated
    truncation: bool,
    /// The responding name server is an authority for the domain name
    /// in question section.
    authoritative_answer: bool,
    /// Kind of query in this message. This value is set by the
    /// originator of a query and copied into the response.
    opcode: Opcode,
    /// Specifies whether this message is a query (false), or a
    /// response (true).
    response: bool,

    // Byte two

    /// Set as part of responses.
    response_code: ResponseCode,
    /// Reserved. Must be zero
    z: u3 = 0,
    /// Set or cleared in a response, and denotes whether recursive
    /// query support is available in the name server.
    recursion_available: bool,

    // End of flag section.

    /// The number of entries in the question section.
    question_count: u16,
    /// The number of resource records in the answer section.
    answer_count: u16,
    /// The number of name server resource records in the authority
    /// records section.
    name_server_count: u16,
    /// The number of resource records in the additional records
    /// section.
    additional_record_count: u16,

    pub const Opcode = enum(u4) {
        query = 0,
        inverse_query = 1,
        status_request = 2,
        _,
    };

    pub const ResponseCode = enum(u4) {
        no_error = 0,
        /// The name server was unable to interpret the query.
        format_error = 1,
        /// The name server was unable to process this query due to a
        /// problem with the name server.
        server_failure = 2,
        /// Meaningful only for responses from an authoritative name
        /// server, this code signifies that the domain name
        /// referenced in the query does not exist.
        name_error = 3,
        ///  The name server does not support the requested kind of
        ///  query.
        not_implemented = 4,
        /// The name server refuses to perform the specified operation
        /// for policy reasons.
        refused = 5,
        _,
    };

    pub fn from_reader(reader: anytype) !Header {
        var bytes = [_]u8{0} ** 12;
        const bytes_read = try reader.readAll(&bytes);
        if (bytes_read < 12) {
            return error.NotEnoughBytes;
        }
        var header = @bitCast(Header, bytes);
        if (builtin.cpu.arch.endian() == .Big) {
            return header;
        }
        header.id = @byteSwap(header.id);
        header.question_count = @byteSwap(header.question_count);
        header.answer_count = @byteSwap(header.answer_count);
        header.name_server_count = @byteSwap(header.name_server_count);
        header.additional_record_count = @byteSwap(header.additional_record_count);
        return header;
    }

    pub fn to_bytes(self: *const Header) [12]u8 {
        var header = self.*;
        if (builtin.cpu.arch.endian() == .Big) {
            return @bitCast([12]u8, header);
        }
        header.id = @byteSwap(header.id);
        header.question_count = @byteSwap(header.question_count);
        header.answer_count = @byteSwap(header.answer_count);
        header.name_server_count = @byteSwap(header.name_server_count);
        header.additional_record_count = @byteSwap(header.additional_record_count);
        return @bitCast([12]u8, header);
    }
};

test "Header.parse simple request" {
    const pkt = @embedFile("test/query.bin");
    const header = Header.parse(pkt[0..@sizeOf(Header)]);
    try std.testing.expectEqual(@as(u16, 23002), header.id);
    try std.testing.expectEqual(false, header.response);
    try std.testing.expectEqual(Header.Opcode.query, header.opcode);
    try std.testing.expectEqual(false, header.authoritative_answer);
    try std.testing.expectEqual(false, header.truncation);
    try std.testing.expectEqual(@as(u16, 1), header.question_count);
    try std.testing.expectEqual(@as(u16, 0), header.name_server_count);
}

test "Header.to_bytes reverses parse" {
    const pkt = @embedFile("test/query.bin");
    const header = Header.parse(pkt[0..@sizeOf(Header)]);
    const bytes = header.to_bytes();
    var orig = [_]u8{0} ** @sizeOf(Header);
    mem.copy(u8, &orig, &bytes);
    try std.testing.expectEqualSlices(u8, &orig, &bytes);
    const header2 = Header.parse(&bytes);
    try std.testing.expectEqual(header, header2);
}

pub const Question = struct {
    qname: DomainName,
    qtype: QType,
    qclass: QClass,

    pub fn to_writer(self: *const Question, writer: anytype) !void {
        try self.qname.to_writer(writer);
        try writer.writeIntBig(u16, @enumToInt(self.qtype));
        try writer.writeIntBig(u16, @enumToInt(self.qclass));
    }

    pub fn from_reader(allocator: mem.Allocator, reader: anytype) !Question {
        const qname = try DomainName.from_reader(allocator, reader);
        var qtype = try reader.readIntBig(u16);
        var qclass = try reader.readIntBig(u16);

        return  Question{
            .qname = qname,
            .qtype = @intToEnum(QType, qtype),
            .qclass = @intToEnum(QClass, qclass),
        };
    }

    pub fn deinit(self: *const Question) void {
        self.qname.deinit();
    }
};

pub const ResourceRecord = struct {
    name: DomainName,
    @"type": Type,
    class: Class,
    ttl: i32,
    resource_data_length: u16,
    resource_data: ResourceData,
};

/// DNS Resource Record types
pub const Type = enum (u16) {
    /// A host address
    A = 1,
    /// An authoritative name server
    NS = 2,
    /// A mail destination (Obsolete - use MX)
    MD = 3,
    /// A mail forwarder (Obsolete - use MX)
    MF = 4,
    /// The canonical name for an alias
    CNAME = 5,
    /// Marks the start of a zone of authority
    SOA = 6,
    /// A mailbox domain name (EXPERIMENTAL)
    MB = 7,
    /// A mail group member (EXPERIMENTAL)
    MG = 8,
    /// A mail rename domain name (EXPERIMENTAL)
    MR = 9,
    /// A null RR (EXPERIMENTAL)
    NULL = 10,
    /// A well known service description
    WKS = 11,
    /// A domain name pointer
    PTR = 12,
    /// Host information
    HINFO = 13,
    /// Mailbox or mail list information
    MINFO = 14,
    /// Mail exchange
    MX = 15,
    /// Text strings
    TXT = 16,

    _,
};

/// QTYPES are a superset of TYPEs, hence all TYPEs are valid QTYPEs.
pub const QType = enum (u16) {
    /// A request for a transfer of an entire zone
    AXFR = 252,
    /// A request for mailbox-related records (MB, MG or MR)
    MAILB = 253,
    /// A request for mail agent RRs (Obsolete - see MX)
    MAILA = 254,
    /// A request for all records
    @"*" = 255,

    _,
};

/// DNS Resource Record Classes
pub const Class = enum (u16) {
    /// The Internet
    IN = 1,
    /// The CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CS = 2,
    /// The CHAOS class
    CH = 3,
    /// Hesiod [Dyer 87]
    HS = 4,
};

/// QCLASS values are a superset of CLASS values; every CLASS is a valid QCLASS.
pub const QClass = enum (u16) {
    /// Any Class
    @"*" = 255,

    _,
};

/// A domain name represented as a sequence of labels, where each
/// label consists of a length octet followed by that number of
/// octets. The domain name terminates with the zero length octet for
/// the null label of the root. Note that this field may be an odd
/// number of octets; no padding is used.
pub const DomainName = struct {
    allocator: mem.Allocator,
    labels: [][]const u8,

    pub fn from_reader(allocator: mem.Allocator, reader: anytype) !DomainName {
        var header = @bitCast(Label.Header, try reader.readByte());
        var labels = StrList.init(allocator);
        while (header.length != 0) {
            var string = try allocator.alloc(u8, header.length);
            const string_length = try reader.readAll(string);
            if (string_length < header.length) {
                return error.NotEnoughBytes;
            }
            try labels.append(string);
            header = @bitCast(Label.Header, try reader.readByte());
        }
        const empty = try allocator.alloc(u8, 0);
        try labels.append(empty);

        return DomainName{
            .allocator = allocator,
            .labels = labels.toOwnedSlice(),
        };
    }

    pub fn to_writer(self: *const DomainName, writer: anytype) !void {
        for (self.labels) |label| {
            if (label.len > std.math.maxInt(Label.Length)) {
                return error.LabelTooLong;
            }
            const header = Label.Header{
                .length = @intCast(u6, label.len),
                .options = .not_compressed,
            };
            const byte = @bitCast(u8, header);
            try writer.writeByte(byte);
            try writer.writeAll(label);
        }
    }

    pub fn from_string(allocator: mem.Allocator, name: []const u8) !DomainName {
        var iter = mem.split(u8, name, ".");
        var str_list = StrList.init(allocator);
        while (iter.next()) |label| {
            if (label.len == 0)
                break;
            const duped = try allocator.dupe(u8, label);
            try str_list.append(duped);
        }
        const empty = try allocator.alloc(u8, 0);
        try str_list.append(empty);
        return DomainName{
            .allocator = allocator,
            .labels = str_list.toOwnedSlice(),
        };
    }

    pub fn deinit(self: *const DomainName) void {
        for (self.labels) |label| {
            self.allocator.free(label);
        }
        self.allocator.free(self.labels);
    }

    // TODO: Proper label compression
    pub const Label = struct {
        // Little bit endian packed struct
        pub const Header = packed struct {
            length: Length,
            options: Options,
        };

        pub const Options = enum(u2) {
            not_compressed = 0,
            compressed = 0b11,
            _,
        };

        pub const Length = u6;
    };
};

test "DomainName" {
    const pkt = @embedFile("test/query.bin");
    const domain = pkt[12..];
    const parsed = try DomainName.parse(testing.allocator, domain);
    defer parsed.deinit();
    try testing.expectEqualStrings("lambda", parsed.labels[0]);
    try testing.expectEqualStrings("cx", parsed.labels[1]);
    try testing.expectEqualStrings("", parsed.labels[2]);
    const bytes = try parsed.to_bytes(testing.allocator);
    defer testing.allocator.free(bytes);
    try testing.expectEqualSlices(u8, domain[0..bytes.len], bytes);
    const from_str = try DomainName.from_string(testing.allocator, "lambda.cx");
    defer from_str.deinit();
    const from_str_bytes = try from_str.to_bytes(testing.allocator);
    defer testing.allocator.free(from_str_bytes);
    try testing.expectEqualSlices(u8, bytes, from_str_bytes);
}

pub const ResourceData = union(enum) {
    cname: CNAME,
    hinfo: HINFO,
    mb: MB,
    md: MD,
    mf: MF,
    mg: MG,
    minfo: MINFO,
    mr: MR,
    mx: MX,
    @"null": NULL,
    ns: NS,
    ptr: PTR,
    soa: SOA,
    txt: TXT,
    a: A,
    wks: WKS,

    pub fn to_writer(self: *const ResourceData, writer: network.Socket.Writer) !void {
        switch (self) {
            inline else => |record| try record.to_writer(writer),
        }
    }

    pub const CNAME = struct {
        /// A domain name which specifies the canonical or primary name
        /// for the owner. The owner name is an alias.
        cname: DomainName,

        pub fn to_writer(self: *const CNAME, writer: anytype) !void {
            try self.cname.to_writer(writer);
        }
    };

    pub const HINFO = struct {
        /// A string which specifies the CPU type.
        cpu: []const u8,
        /// A string which specifies the operating system type.
        os:  []const u8,

        pub fn to_writer(self: *const HINFO, writer: anytype) !void {
            try writer.writeAll(self.cpu);
            try writer.writeByte(0);
            try writer.writeAll(self.os);
            try writer.writeByte(0);
        }
    };

    pub const MB = struct {
        /// A domain name which specifies a host which has the specified
        /// mailbox.
        madname: DomainName,

        pub fn to_writer(self: *const MB, writer: anytype) !void {
            try self.madname.to_writer(writer);
        }
    };

    pub const MD = struct {
        /// A domain name which specifies a host which has a mail agent
        /// for the domain which should be able to deliver mail for the
        /// domain.
        madname: DomainName,

        pub fn to_writer(self: *const MD, writer: anytype) !void {
            try self.madname.to_writer(writer);
        }
    };

    pub const MF = struct {
        /// A domain name which specifies a host which has a mail agent
        /// for the domain which will accept mail for forwarding to the
        /// domain.
        madname: DomainName,

        pub fn to_writer(self: *const MD, writer: anytype) !void {
            try self.madname.to_writer(writer);
        }
    };

    pub const MG = struct {
        /// A domain name which specifies a mailbox which is a member of
        /// the mail group specified by the domain name.
        madname: DomainName,

        pub fn to_writer(self: *const MG, writer: anytype) !void {
            try self.madname.to_writer(writer);
        }
    };

    pub const MINFO = struct {
        /// A domain name which specifies a mailbox which is responsible
        /// for the mailing list or mailbox. If this domain name names the
        /// root, the owner of the MINFO RR is responsible for itself.
        /// Note that many existing mailing lists use a mailbox X-request
        /// for the RMAILBX field of mailing list X, e.g., Msgroup-request
        /// for Msgroup. This field provides a more general mechanism.
        rmailbx: DomainName,
        /// A domain name which specifies a mailbox which is to receive
        /// error messages related to the mailing list or mailbox
        /// specified by the owner of the MINFO RR (similar to the
        /// ERRORS-TO: field which has been proposed). If this domain name
        /// names the root, errors should be returned to the sender of the
        /// message.
        emailbx: DomainName,

        pub fn to_writer(self: *const MINFO, writer: anytype) !void {
            try self.rmailbx.to_writer(writer);
            try self.emailbx.to_writer(writer);
        }
    };

    pub const MR = struct {
        /// A domain name which specifies a mailbox which is the proper
        /// rename of the specified mailbox.
        madname: DomainName,

        pub fn to_writer(self: *const MR, writer: anytype) !void {
            try self.madname.to_writer(writer);
        }
    };

    pub const MX = struct {
        /// A 16 bit integer which specifies the preference given to this
        /// RR among others at the same owner. Lower values are preferred.
        preference: u16,
        /// A domain name which specifies a host willing to act as a
        /// mail exchange for the owner name.
        exchange: DomainName,

        pub fn to_writer(self: *const MX, writer: anytype) !void {
            try writer.writeIntBig(u16, self.preference);
            try self.exchange.to_writer(writer);
        }
    };

    pub const NULL = struct {
        data: []const u8,

        pub fn to_writer(self: *const NULL, writer: anytype) !void {
            try writer.writeAll(self.data);
        }
    };

    pub const NS = struct {
        /// A domain name which specifies a host which should be
        /// authoritative for the specified class and domain.
        nsdname: DomainName,

        pub fn to_writer(self: *const NS, writer: anytype) !void {
            try self.nsdname.to_writer(writer);
        }
    };

    pub const PTR = struct {
        /// A domain name which points to some location in the domain name
        /// space.
        ptrdname: DomainName,

        pub fn to_writer(self: *const PTR, writer: anytype) !void {
            try self.ptrdname.to_writer(writer);
        }
    };

    pub const SOA = struct {
        /// The domain name of the name server that was the original or
        /// primary source of data for this zone.
        mname: DomainName,
        /// A domain name which specifies the mailbox of the person
        /// responsible for this zone.
        rname: DomainName,
        /// The version number of the original copy of the zone. Zone
        /// transfers preserve this value. This value wraps and should be
        /// compared using sequence space arithmetic.
        serial: u32,
        /// A time interval before the zone should be refreshed.
        refresh: i32,
        /// A time interval that should elapse before a failed refresh
        /// should be retried.
        retry: i32,
        /// A value that specifies the upper limit on the time interval
        /// that can elapse before the zone is no longer authoritative.
        expire: i32,
        /// The minimum TTL field that should be exported with any RR from
        /// this zone.
        minimum: u32,

        pub fn to_writer(self: *const SOA, writer: network.Socket.Writer) !void {
            try self.mname.to_writer(writer);
            try self.rname.to_writer(writer);
            try writer.writeIntBig(u32, self.serial);
            try writer.writeIntBig(i32, self.refresh);
            try writer.writeIntBig(i32, self.retry);
            try writer.writeIntBig(i32, self.expire);
            try writer.writeIntBig(u32, self.minimum);
        }
    };

    pub const TXT = struct {
        /// One or more strings.
        txt_data: []const u8,

        pub fn to_writer(self: *const TXT, writer: anytype) !void {
            try writer.writeAll(self.txt_data);
            try writer.writeByte(0);
        }
    };

    pub const A = struct {
        /// An internet address
        address: [4]u8,

        pub fn to_writer(self: *const A, writer: anytype) !void {
            // XXX This may be incorrect endianness
            try writer.writeAll(self.address);
            // try writer.writeIntBig(u32, self.address.sa.addr);
        }
    };

    pub const WKS = struct {
        /// An internet address
        address: [4]u8,
        /// An IP protocol number
        protocol: u8,
        /// A variable length bit map.
        bit_map: []const u8,

        pub fn to_writer(self: *const WKS, writer: network.Socket.Writer) !void {
            try writer.writeAll(self.address);
            try writer.writeByte(self.protocol);
            try writer.writeAll(self.bit_map);
        }
    };
};
