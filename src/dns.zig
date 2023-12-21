// Copyright (c) 2022-2023 Dante Catalfamo
// SPDX-License-Identifier: MIT

const std = @import("std");
const mem = std.mem;
const io = std.io;
const testing = std.testing;
const builtin = @import("builtin");

const StrList = std.ArrayList([]const u8);
const LabelList = std.ArrayList(DomainName.Label);
const QuestionList = std.ArrayList(Question);
const ResourceRecordList = std.ArrayList(ResourceRecord);

/// Creates a DNS query message with common defaults.
pub fn createQuery(allocator: mem.Allocator, address: []const u8, qtype: QType) !Message {
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

    const domain = try DomainName.from_string(allocator, address);

    const question = Question{
        .qname = domain,
        .qtype = qtype,
        .qclass = @enumFromInt(@intFromEnum(Class.IN)),
    };
    var questions = try allocator.alloc(Question, 1);
    questions[0] = question;

    const message = Message{
        .allocator = allocator,
        .header = header,
        .questions = questions,
        .answers = &.{},
        .authorities = &.{},
        .additional = &.{}
    };

    return message;
}

pub const EDNS = struct {
    bufsize: u16 = 1232,
    do_dnssec: bool = true,
    // In the future, EDNS options will come here

    pub fn format(self: *const EDNS, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        _ = fmt; // We don't use these two parameters
        _ = options;
        try writer.print("  EDNS {{\n", .{});
        try writer.print("    Payload size: {d}\n", .{self.bufsize});
        try writer.print("    Do DNSSEC: {any}\n", .{self.do_dnssec});
        try writer.print("  }}\n", .{});
    }
};

pub const PackedEDNSTTL = packed struct(u32) {
    z2: u8 = 0,
    z1: u7 = 0, // Zig put fields in the unexpected order inside a byte.
    do: bool = true,
    version: u8 = 0, // EDNS version 0 (RFC 6891)
    extendedRcode: u8 = 0,
};

pub fn createEDNSQuery(allocator: mem.Allocator, address: []const u8, qtype: QType, edns: EDNS) !Message {
    var result = try createQuery(allocator, address, qtype);
    result.header.additional_record_count += 1;
    const domain = try DomainName.from_string(allocator, ".");
    var flags = PackedEDNSTTL{};
    flags.do = edns.do_dnssec;
    const rr: ResourceRecord = .{
        .name = domain,
        .type = Type.OPT,
        .class = @enumFromInt(edns.bufsize),
        .ttl = @as(i32, @bitCast(flags)),
        .resource_data_length = 0, // We do not yet handle EDNS options ({attribute,value} pairs)
        .resource_data = ResourceData{ .null = undefined },
    };
    var rrset = ResourceRecordList.init(allocator);
    defer listDeinit(rrset);
    try rrset.append(rr);
    result.additional = try rrset.toOwnedSlice();
    return result;
}

/// DNS Message. All communications inside of the domain protocol are
/// carried in a single format called a message.
pub const Message = struct {
    allocator: mem.Allocator,
    /// Contains information about the message. The header section is
    /// always present
    header: Header,
    // EDNS information
    edns: ?EDNS = null,
    /// The question(s) being asked in the query. This section usually
    /// contains one question.
    questions: []const Question,
    /// ResourceRecords answering the question.
    answers: []const ResourceRecord,
    /// ResourceRecords pointing toward an authority.
    authorities: []const ResourceRecord,
    /// ResourceRecords holding additional information.
    additional: []const ResourceRecord,

    pub fn to_writer(self: *const Message, writer: anytype) !void {
        try writer.writeAll(&self.header.to_bytes());
        for (self.questions) |question| {
            try question.to_writer(writer);
        }
        for (self.answers) |answer| {
            try answer.to_writer(writer);
        }
        for (self.authorities) |authority| {
            try authority.to_writer(writer);
        }
        for (self.additional) |addition| {
            try addition.to_writer(writer);
        }
    }

    /// Not decompressed
    pub fn from_reader(allocator: mem.Allocator, reader: anytype) !Message {
        const header = try Header.from_reader(reader);

        var questions = QuestionList.init(allocator);
        errdefer listDeinit(questions);

        var q_idx: usize = 0;
        while (q_idx < header.question_count) : (q_idx += 1) {
            const question = try Question.from_reader(allocator, reader);
            try questions.append(question);
        }

        var answers = ResourceRecordList.init(allocator);
        errdefer listDeinit(answers);

        var ans_idx: usize = 0;
        while (ans_idx < header.answer_count) : (ans_idx += 1) {
            const answer = try ResourceRecord.from_reader(allocator, reader);
            try answers.append(answer);
        }

        var authorities = ResourceRecordList.init(allocator);
        errdefer listDeinit(authorities);

        var auth_idx: usize = 0;
        while (auth_idx < header.name_server_count) : (auth_idx += 1) {
            const authority = try ResourceRecord.from_reader(allocator, reader);
            try authorities.append(authority);
        }

        var additional = ResourceRecordList.init(allocator);
        errdefer listDeinit(additional);

        var add_idx: usize = 0;
        var edns: ?EDNS = null;
        while (add_idx < header.additional_record_count) : (add_idx += 1) {
            const addit = try ResourceRecord.from_reader(allocator, reader);
            if (addit.type == Type.OPT) {
                const flags: PackedEDNSTTL = @as(PackedEDNSTTL, @bitCast(addit.ttl));
                const do: bool = flags.do;
                edns = .{ .bufsize = @intFromEnum(addit.class), .do_dnssec = do };
            } else {
                try additional.append(addit);
            }
        }
        return Message{
            .allocator = allocator,
            .header = header,
            .edns = edns,
            .questions = try questions.toOwnedSlice(),
            .answers = try answers.toOwnedSlice(),
            .authorities = try authorities.toOwnedSlice(),
            .additional = try additional.toOwnedSlice(),
        };
    }

    /// Automatically decompressed
    pub fn from_bytes(allocator: mem.Allocator, bytes: []const u8) !Message {
        var buffer = io.fixedBufferStream(bytes);
        const reader = buffer.reader();
        const message = try Message.from_reader(allocator, reader);
        defer message.deinit();
        const decompressed = try message.decompress(allocator, bytes);
        return decompressed;
    }

    pub fn to_bytes(self: *const Message, allocator: mem.Allocator) ![]const u8 {
        var bytes = std.ArrayList(u8).init(allocator);
        const writer = bytes.writer();
        try self.to_writer(writer);
        return bytes.toOwnedSlice();
    }

    pub fn deinit(self: *const Message) void {
        for (self.questions) |question| {
            question.deinit();
        }
        self.allocator.free(self.questions);
        for (self.answers) |answer| {
            answer.deinit();
        }
        self.allocator.free(self.answers);
        for (self.authorities) |authority| {
            authority.deinit();
        }
        self.allocator.free(self.authorities);
        for (self.additional) |addit| {
            addit.deinit();
        }
        self.allocator.free(self.additional);
    }

    pub fn format(self: *const Message, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        _ = fmt;
        _ = options;
        try writer.print("Message {{\n", .{});
        try writer.print("{any}", .{self.header});
        if (self.edns != null) {
            try writer.print("{any}", .{self.edns});
        }
        try writer.print("  Questions {{\n", .{});
        for (self.questions) |question| {
            try writer.print("{any}", .{question});
        }
        try writer.print("  }}\n", .{});
        try writer.print("  Answers {{\n", .{});
        for (self.answers) |answer| {
            try writer.print("{any}", .{answer});
        }
        try writer.print("  }}\n", .{});
        try writer.print("  Authorities {{\n", .{});
        for (self.authorities) |authority| {
            try writer.print("{any}", .{authority});
        }
        try writer.print("  }}\n", .{});
        try writer.print("  Additional {{\n", .{});
        for (self.additional) |addition| {
            try writer.print("{any}", .{addition});
        }
        try writer.print("  }}\n", .{});
        try writer.print("}}\n", .{});
    }

    /// Creates a deep copy of the original message, with all message
    /// pointers resolved
    pub fn decompress(self: *const Message, allocator: mem.Allocator, packet: []const u8) !Message {
        var questions = QuestionList.init(allocator);
        errdefer listDeinit(questions);
        var answers = ResourceRecordList.init(allocator);
        errdefer listDeinit(answers);
        var authorities = ResourceRecordList.init(allocator);
        errdefer listDeinit(authorities);
        var additional = ResourceRecordList.init(allocator);
        errdefer listDeinit(additional);

        for (self.questions) |question| {
            const new_question = try question.decompress(allocator, packet);
            errdefer new_question.deinit();
            try questions.append(new_question);
        }

        for (self.answers) |answer| {
            const new_answer = try answer.decompress(allocator, packet);
            errdefer new_answer.deinit();
            try answers.append(new_answer);
        }

        for (self.authorities) |authority| {
            const new_authority = try authority.decompress(allocator, packet);
            errdefer new_authority.deinit();
            try authorities.append(new_authority);
        }

        for (self.additional) |addition| {
            const new_addition = try addition.decompress(allocator, packet);
            errdefer new_addition.deinit();
            try additional.append(new_addition);
        }

        const message = Message{
            .allocator = self.allocator,
            .header = self.header,
            .edns = self.edns,
            .questions = try questions.toOwnedSlice(),
            .answers = try answers.toOwnedSlice(),
            .authorities = try authorities.toOwnedSlice(),
            .additional = try additional.toOwnedSlice(),
        };

        return message;
    }
};

/// DNS message header. Contains information about the message.
pub const Header = packed struct(u96) {
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
        var header: Header = @bitCast(bytes);
        if (builtin.cpu.arch.endian() == .big) {
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
        if (builtin.cpu.arch.endian() == .big) {
            return @bitCast(header);
        }
        header.id = @byteSwap(header.id);
        header.question_count = @byteSwap(header.question_count);
        header.answer_count = @byteSwap(header.answer_count);
        header.name_server_count = @byteSwap(header.name_server_count);
        header.additional_record_count = @byteSwap(header.additional_record_count);
        return @as([12]u8, @bitCast(header));
    }

    pub fn to_writer(self: *const Header, writer: anytype) !void {
        const header = self.to_bytes();
        try writer.writeAll(header);
    }

    pub fn format(self: *const Header, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        _ = fmt;
        _ = options;
        try writer.print("  Header {{\n", .{});
        try writer.print("    ID: {d}\n", .{self.id});
        try writer.print("    Response: {}\n", .{self.response});
        try writer.print("    OpCode: {s}\n", .{@tagName(self.opcode)});
        try writer.print("    Authoritative Answer: {}\n", .{self.authoritative_answer});
        try writer.print("    Truncation: {}\n", .{self.truncation});
        try writer.print("    Recursion Desired: {}\n", .{self.recursion_desired});
        try writer.print("    Recursion Available: {}\n", .{self.recursion_available});
        try writer.print("    Z: {d}\n", .{self.z});
        try writer.print("    Response Code: {s}\n", .{@tagName(self.response_code)});
        try writer.print("  }}\n", .{});
    }
};

test "Header.parse simple request" {
    return error.SkipZigTest;
    // const pkt = @embedFile("test/query.bin");
    // const header = Header.parse(pkt[0..@sizeOf(Header)]);
    // try std.testing.expectEqual(@as(u16, 23002), header.id);
    // try std.testing.expectEqual(false, header.response);
    // try std.testing.expectEqual(Header.Opcode.query, header.opcode);
    // try std.testing.expectEqual(false, header.authoritative_answer);
    // try std.testing.expectEqual(false, header.truncation);
    // try std.testing.expectEqual(@as(u16, 1), header.question_count);
    // try std.testing.expectEqual(@as(u16, 0), header.name_server_count);
}

test "Header.to_bytes reverses parse" {
    return error.SkipZigTest;
    // const pkt = @embedFile("test/query.bin");
    // const header = Header.parse(pkt[0..@sizeOf(Header)]);
    // const bytes = header.to_bytes();
    // var orig = [_]u8{0} ** @sizeOf(Header);
    // mem.copy(u8, &orig, &bytes);
    // try std.testing.expectEqualSlices(u8, &orig, &bytes);
    // const header2 = Header.parse(&bytes);
    // try std.testing.expectEqual(header, header2);
}

/// Question being asked in the query.
pub const Question = struct {
    qname: DomainName,
    qtype: QType,
    qclass: QClass,

    pub fn to_writer(self: *const Question, writer: anytype) !void {
        try self.qname.to_writer(writer);
        try writer.writeInt(u16, @intFromEnum(self.qtype), .big);
        try writer.writeInt(u16, @intFromEnum(self.qclass), .big);
    }

    pub fn from_reader(allocator: mem.Allocator, reader: anytype) !Question {
        const qname = try DomainName.from_reader(allocator, reader);
        const qtype = try reader.readInt(u16, .big);
        const qclass = try reader.readInt(u16, .big);

        return Question{
            .qname = qname,
            .qtype = @enumFromInt(qtype),
            .qclass = @enumFromInt(qclass),
        };
    }

    pub fn deinit(self: *const Question) void {
        self.qname.deinit();
    }

    pub fn format(self: *const Question, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        _ = fmt;
        _ = options;

        try writer.print("    Question {{\n", .{});
        try writer.print("      Name: {}\n", .{self.qname});
        try writer.print("      QType: {s}\n", .{@tagName(self.qtype)});
        try writer.print("      QClass: {s}\n", .{@tagName(self.qclass)});
        try writer.print("    }}\n", .{});
    }

    pub fn decompress(self: *const Question, allocator: mem.Allocator, packet: []const u8) !Question {
        return Question{
            .qname = try self.qname.decompress(allocator, packet),
            .qtype = self.qtype,
            .qclass = self.qclass,
        };
    }
};

/// Shared by the answer, authority, and additional sections of the
/// message.
pub const ResourceRecord = struct {
    name: DomainName,
    type: Type,
    class: Class,
    ttl: i32,
    resource_data_length: u16,
    resource_data: ResourceData,

    pub fn to_writer(self: *const ResourceRecord, writer: anytype) !void {
        var resource_data = [_]u8{0} ** std.math.maxInt(u16);
        var resource_data_stream = std.io.fixedBufferStream(&resource_data);

        try self.resource_data.to_writer(resource_data_stream.writer());

        try self.name.to_writer(writer);
        try writer.writeInt(u16, @intFromEnum(self.type), .big);
        try writer.writeInt(u16, @intFromEnum(self.class), .big);
        try writer.writeInt(i32, self.ttl, .big);
        try writer.writeInt(u16, @as(u16, @intCast(try resource_data_stream.getPos())), .big);
        try writer.writeAll(resource_data_stream.getWritten());
    }

    pub fn from_reader(allocator: mem.Allocator, reader: anytype) !ResourceRecord {
        const name = try DomainName.from_reader(allocator, reader);
        errdefer name.deinit();
        const resource_type: Type = @enumFromInt(try reader.readInt(u16, .big));
        const class: Class = @enumFromInt(try reader.readInt(u16, .big));
        const ttl = try reader.readInt(i32, .big);
        const resource_data_length = try reader.readInt(u16, .big);
        var counting_reader = io.countingReader(reader);
        const resource_data = try ResourceData.from_reader(allocator, counting_reader.reader(), resource_type, resource_data_length);
        if (counting_reader.bytes_read != resource_data_length) {
            return error.ResourceDataSizeMismatch;
        }

        return .{
            .name = name,
            .type = resource_type,
            .class = class,
            .ttl = ttl,
            .resource_data_length = resource_data_length,
            .resource_data = resource_data,
        };
    }

    pub fn deinit(self: *const ResourceRecord) void {
        self.name.deinit();
        self.resource_data.deinit();
    }

    pub fn format(self: *const ResourceRecord, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        _ = fmt;
        _ = options;

        try writer.print("    Resource Record {{\n", .{});
        try writer.print("      Name: {}\n", .{self.name});
        try writer.print("      Type: {}\n", .{self.type});
        try writer.print("      Class: {}\n", .{self.class});
        try writer.print("      TTL: {d}\n", .{self.ttl});
        try writer.print("      Resource Data Length: {d}\n", .{self.resource_data_length});
        try writer.print("      Resource Data: {}\n", .{self.resource_data});
        try writer.print("    }}\n", .{});
    }

    pub fn decompress(self: *const ResourceRecord, allocator: mem.Allocator, packet: []const u8) !ResourceRecord {
        const new_record = try self.resource_data.decompress(allocator, packet);
        return ResourceRecord{
            .name = try self.name.decompress(allocator, packet),
            .type = self.type,
            .class = self.class,
            .ttl = self.ttl,
            // XXX Should update?
            .resource_data_length = self.resource_data_length,
            .resource_data = new_record,
        };
    }
};

/// DNS Resource Record types https://www.iana.org/assignments/dns-parameters/dns-parameters.xml#dns-parameters-4
pub const Type = enum(u16) {
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
    /// Responsible Person
    RP = 17,
    /// An IPv6 host address
    AAAA = 28,
    /// Location information
    LOC = 29,
    /// Service locator
    SRV = 33,
    // EDNS record
    OPT = 41,
    /// SSH Fingerprint
    SSHFP = 44,
    /// Uniform Resource Identifier
    URI = 256,

    _,

    pub fn format(self: Type, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        _ = fmt;
        _ = options;
        try formatTagName(self, writer);
    }
};

/// Types exclusive to QType.
pub const QTypeOnly = enum(u16) {
    /// A request for a transfer of an entire zone
    AXFR = 252,
    /// A request for mailbox-related records (MB, MG or MR)
    MAILB = 253,
    /// A request for mail agent RRs (Obsolete - see MX)
    MAILA = 254,
    /// A request for all records
    @"*" = 255,
};

/// QTYPES are a superset of TYPEs, hence all TYPEs are valid QTYPEs.
pub const QType = blk: {
    var info = @typeInfo(Type);
    info.Enum.fields = info.Enum.fields ++ @typeInfo(QTypeOnly).Enum.fields;
    info.Enum.decls = &.{};
    break :blk @Type(info);
};

/// DNS Resource Record Classes
pub const Class = enum(u16) {
    /// The Internet
    IN = 1,
    /// The CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CS = 2,
    /// The CHAOS class
    CH = 3,
    /// Hesiod [Dyer 87]
    HS = 4,
    _, // Non-exhaustive enums for EDNS, where "class" is the payload size

    pub fn format(self: Class, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        _ = fmt;
        _ = options;
        try formatTagName(self, writer);
    }
};

/// Classes exclusive to QClass.
pub const QClassOnly = enum(u16) {
    /// Any Class
    @"*" = 255,
};

/// QCLASS values are a superset of CLASS values; every CLASS is a valid QCLASS.
pub const QClass = blk: {
    var info = @typeInfo(Class);
    info.Enum.fields = info.Enum.fields ++ @typeInfo(QClassOnly).Enum.fields;
    info.Enum.decls = &.{};
    break :blk @Type(info);
};

/// A domain name represented as a sequence of labels, where each
/// label consists of a length octet followed by that number of
/// octets. The domain name terminates with the zero length octet for
/// the null label of the root. Note that this field may be an odd
/// number of octets; no padding is used.
pub const DomainName = struct {
    allocator: mem.Allocator,
    labels: []Label,

    pub fn from_reader(allocator: mem.Allocator, reader: anytype) !DomainName {
        var labels = LabelList.init(allocator);
        var header_byte = try reader.readByte();
        errdefer {
            for (labels.items) |label| {
                switch (label) {
                    .text => |text| allocator.free(text),
                    else => {},
                }
            }
            labels.deinit();
        }
        outer: while (true) {
            const label_options: Label.Options = @enumFromInt(header_byte >> 6);
            switch (label_options) {
                .text => {
                    const header: Label.TextHeader = @bitCast(header_byte);
                    if (header.length == 0) {
                        break :outer;
                    }
                    const string = try allocator.alloc(u8, header.length);
                    errdefer allocator.free(string);
                    const string_length = try reader.readAll(string);
                    if (string_length < header.length) {
                        return error.EndOfStream;
                    }
                    const label = Label{
                        .text = string,
                    };
                    try labels.append(label);
                },
                .compressed => {
                    const header: Label.TextHeader = @bitCast(header_byte);
                    const pointer_end = try reader.readByte();
                    // XXX Different on big-endian systems?
                    const components = Label.PointerComponents{ .upper = header.length, .lower = pointer_end };
                    const pointer: Label.Pointer = @bitCast(components);
                    const label = Label{
                        .compressed = pointer,
                    };
                    try labels.append(label);
                    break :outer;
                },
                else => {
                    return error.UnsupportedLabel;
                },
            }
            header_byte = try reader.readByte();
        }

        const empty = Label{
            .text = try allocator.alloc(u8, 0),
        };
        errdefer allocator.free(empty.text);
        try labels.append(empty);

        return DomainName{
            .allocator = allocator,
            .labels = try labels.toOwnedSlice(),
        };
    }

    pub fn to_writer(self: *const DomainName, writer: anytype) !void {
        for (self.labels) |label| {
            switch (label) {
                .text => |text| {
                    if (text.len > std.math.maxInt(Label.Length)) {
                        return error.LabelTooLong;
                    }
                    const header = Label.TextHeader{ .length = @intCast(text.len), .options = .text };
                    const header_byte: u8 = @bitCast(header);
                    try writer.writeByte(header_byte);
                    try writer.writeAll(text);
                },
                .compressed => |pointer| {
                    const pointer_components: Label.PointerComponents = @bitCast(pointer);
                    const header = Label.TextHeader{
                        .length = pointer_components.upper,
                        .options = .compressed,
                    };
                    const header_byte: u8 = @bitCast(header);
                    try writer.writeByte(header_byte);
                    try writer.writeByte(pointer_components.lower);
                },
                // else => return error.UnsupportedLabel,
            }
        }
    }

    pub fn from_string(allocator: mem.Allocator, name: []const u8) !DomainName {
        var iter = mem.split(u8, name, ".");
        var labels = LabelList.init(allocator);

        errdefer {
            for (labels.items) |label| {
                switch (label) {
                    .text => |text| allocator.free(text),
                    else => {},
                }
            }
            labels.deinit();
        }

        while (iter.next()) |text| {
            if (text.len == 0)
                break;
            const duped = try allocator.dupe(u8, text);
            const label = Label{
                .text = duped,
            };
            try labels.append(label);
        }
        const empty = try allocator.alloc(u8, 0);
        errdefer allocator.free(empty);
        const label = Label{
            .text = empty,
        };
        try labels.append(label);
        return DomainName{
            .allocator = allocator,
            .labels = try labels.toOwnedSlice(),
        };
    }

    pub fn to_string(self: *const DomainName, allocator: mem.Allocator) ![]const u8 {
        var string = std.ArrayList(u8).init(allocator);
        errdefer string.deinit();

        for (self.labels) |label| {
            switch (label) {
                .text => |text| {
                    if (text.len == 0) {
                        continue;
                    }
                    try string.appendSlice(text);
                    try string.appendSlice(".");
                },
                .compressed => |pointer| {
                    var writer = string.writer();
                    try writer.print("Pointer<{d}>", .{pointer});
                },
            }
        }
        return try string.toOwnedSlice();
    }

    pub fn format(self: *const DomainName, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        _ = fmt;
        _ = options;

        for (self.labels) |label| {
            switch (label) {
                .text => |text| {
                    if (text.len == 0) {
                        continue;
                    }
                    try writer.print("{s}.", .{text});
                },
                .compressed => |pointer| {
                    try writer.print("Pointer<{d}>", .{pointer});
                },
            }
        }
    }

    pub fn deinit(self: *const DomainName) void {
        for (self.labels) |label| {
            switch (label) {
                .text => self.allocator.free(label.text),
                else => {},
            }
        }
        self.allocator.free(self.labels);
    }

    /// Returns a completely newly allocated DomainName
    pub fn decompress(self: *const DomainName, allocator: mem.Allocator, packet: []const u8) !DomainName {
        var labels = LabelList.init(allocator);

        errdefer {
            for (labels.items) |label| {
                switch (label) {
                    .text => |text| allocator.free(text),
                    .compressed => {},
                }
            }
            labels.deinit();
        }

        var depth: usize = 0;
        var pointer: ?Label.Pointer = null;
        for (self.labels) |label| {
            switch (label) {
                .text => |text| {
                    const duped = try allocator.dupe(u8, text);
                    errdefer allocator.free(duped);
                    const new_label = Label{ .text = duped };
                    try labels.append(new_label);
                },
                .compressed => |ptr| {
                    pointer = ptr;
                    break;
                },
            }
        }

        while (pointer) |valid_pointer| {
            if (depth > max_compression_depth) {
                return error.CompressionDepth;
            }
            var buffer = io.fixedBufferStream(packet);
            const reader = buffer.reader();
            buffer.pos = valid_pointer;
            const domain = try DomainName.from_reader(allocator, reader);
            defer domain.deinit();
            pointer = null;
            for (domain.labels) |label| {
                switch (label) {
                    .text => |text| {
                        const duped = try allocator.dupe(u8, text);
                        errdefer allocator.free(duped);
                        const new_label = Label{ .text = duped };
                        try labels.append(new_label);
                    },
                    .compressed => |ptr| {
                        pointer = ptr;
                        depth += 1;
                        break;
                    },
                }
            }
        }

        return DomainName{
            .allocator = allocator,
            .labels = try labels.toOwnedSlice(),
        };
    }

    pub const max_compression_depth = 25;

    // TODO: Proper label compression
    pub const Label = union(enum) {
        text: []const u8,
        compressed: Pointer,
        // Little bit endian packed struct
        pub const TextHeader = packed struct {
            length: Length,
            options: Options,
        };

        pub const Options = enum(u2) {
            text = 0,
            compressed = 0b11,
            _,
        };

        pub const PointerComponents = packed struct {
            lower: u8,
            upper: u6,
        };

        pub const Length = u6;
        pub const Pointer = u14;
    };
};

test "DomainName" {
    return error.SkipZigTest;
    // const pkt = @embedFile("test/query.bin");
    // const domain = pkt[12..];
    // const parsed = try DomainName.parse(testing.allocator, domain);
    // defer parsed.deinit();
    // try testing.expectEqualStrings("lambda", parsed.labels[0]);
    // try testing.expectEqualStrings("cx", parsed.labels[1]);
    // try testing.expectEqualStrings("", parsed.labels[2]);
    // const bytes = try parsed.to_bytes(testing.allocator);
    // defer testing.allocator.free(bytes);
    // try testing.expectEqualSlices(u8, domain[0..bytes.len], bytes);
    // const from_str = try DomainName.from_string(testing.allocator, "lambda.cx");
    // defer from_str.deinit();
    // const from_str_bytes = try from_str.to_bytes(testing.allocator);
    // defer testing.allocator.free(from_str_bytes);
    // try testing.expectEqualSlices(u8, bytes, from_str_bytes);
}

/// The data section of a ResourceRecord. Different based on the
/// record type.
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
    null: NULL,
    ns: NS,
    ptr: PTR,
    soa: SOA,
    txt: TXT,
    a: A,
    wks: WKS,
    rp: RP,
    aaaa: AAAA,
    loc: LOC,
    srv: SRV,
    sshfp: SSHFP,
    uri: URI,
    unknown: Unknown,

    pub fn to_writer(self: *const ResourceData, writer: anytype) !void {
        switch (self.*) {
            inline else => |record| try record.to_writer(writer),
        }
    }

    pub fn from_reader(allocator: mem.Allocator, reader: anytype, resource_type: Type, size: u16) !ResourceData {
        return switch (resource_type) {
            .CNAME => ResourceData{ .cname   = try   CNAME.from_reader(allocator, reader, size) },
            .HINFO => ResourceData{ .hinfo   = try   HINFO.from_reader(allocator, reader, size) },
            .MB    => ResourceData{ .mb      = try      MB.from_reader(allocator, reader, size) },
            .MD    => ResourceData{ .md      = try      MD.from_reader(allocator, reader, size) },
            .MF    => ResourceData{ .mf      = try      MF.from_reader(allocator, reader, size) },
            .MG    => ResourceData{ .mg      = try      MG.from_reader(allocator, reader, size) },
            .MINFO => ResourceData{ .minfo   = try   MINFO.from_reader(allocator, reader, size) },
            .MR    => ResourceData{ .mr      = try      MR.from_reader(allocator, reader, size) },
            .MX    => ResourceData{ .mx      = try      MX.from_reader(allocator, reader, size) },
            .NULL  => ResourceData{ .null    = try    NULL.from_reader(allocator, reader, size) },
            .NS    => ResourceData{ .ns      = try      NS.from_reader(allocator, reader, size) },
            .PTR   => ResourceData{ .ptr     = try     PTR.from_reader(allocator, reader, size) },
            .SOA   => ResourceData{ .soa     = try     SOA.from_reader(allocator, reader, size) },
            .TXT   => ResourceData{ .txt     = try     TXT.from_reader(allocator, reader, size) },
            .A     => ResourceData{ .a       = try       A.from_reader(allocator, reader, size) },
            .WKS   => ResourceData{ .wks     = try     WKS.from_reader(allocator, reader, size) },
            .RP    => ResourceData{ .rp      = try      RP.from_reader(allocator, reader, size) },
            .AAAA  => ResourceData{ .aaaa    = try    AAAA.from_reader(allocator, reader, size) },
            .LOC   => ResourceData{ .loc     = try     LOC.from_reader(allocator, reader, size) },
            .SRV   => ResourceData{ .srv     = try     SRV.from_reader(allocator, reader, size) },
            .SSHFP => ResourceData{ .sshfp   = try   SSHFP.from_reader(allocator, reader, size) },
            else => ResourceData{ .unknown   = try Unknown.from_reader(allocator, reader, size) },
        };
    }

    pub fn decompress(self: ResourceData, allocator: mem.Allocator, packet: []const u8) !ResourceData {
        return switch (self) {
            inline else => |inner, tag| @unionInit(ResourceData, @tagName(tag), try inner.decompress(allocator, packet)),
        };
    }

    pub fn deinit(self: *const ResourceData) void {
        switch (self.*) {
            inline else => |record| record.deinit(),
        }
    }

    pub fn format(self: *const ResourceData, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        _ = fmt;
        _ = options;
        switch (self.*) {
            inline else => |resource| try writer.print("{}", .{resource}),
        }
    }

    pub const CNAME = struct {
        /// A domain name which specifies the canonical or primary name
        /// for the owner. The owner name is an alias.
        cname: DomainName,

        pub fn to_writer(self: *const CNAME, writer: anytype) !void {
            try self.cname.to_writer(writer);
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, _: u16) !CNAME {
            return .{
                .cname = try DomainName.from_reader(allocator, reader),
            };
        }

        pub fn deinit(self: *const CNAME) void {
            self.cname.deinit();
        }

        pub fn format(self: *const CNAME, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print("{}", .{self.cname});
        }

        pub fn decompress(self: CNAME, allocator: mem.Allocator, packet: []const u8) !CNAME {
            return .{
                .cname = try self.cname.decompress(allocator, packet),
            };
        }
    };

    pub const HINFO = struct {
        allocator: mem.Allocator,
        /// A string which specifies the CPU type.
        cpu: []const u8,
        /// A string which specifies the operating system type.
        os: []const u8,

        pub fn to_writer(self: *const HINFO, writer: anytype) !void {
            if (self.cpu.len > 255) {
                return error.CpuStringTooLong;
            }
            if (self.os.len > 255) {
                return error.OsStringTooLong;
            }
            try writer.writeByte(@intCast(self.cpu.len));
            try writer.writeAll(self.cpu);
            try writer.writeByte(@intCast(self.os.len));
            try writer.writeAll(self.os);
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, _: u16) !HINFO {
            const cpu = try allocator.alloc(u8, try reader.readByte());
            errdefer allocator.free(cpu);
            const cpu_len = try reader.readAll(cpu);
            if (cpu_len < cpu.len) {
                return error.EndOfStream;
            }
            const os = try allocator.alloc(u8, try reader.readByte());
            errdefer allocator.free(os);
            const os_len = try reader.readAll(os);
            if (os_len < os.len) {
                return error.EndOfStream;
            }

            return .{
                .allocator = allocator,
                .cpu = cpu,
                .os = os,
            };
        }

        pub fn deinit(self: *const HINFO) void {
            self.allocator.free(self.cpu);
            self.allocator.free(self.os);
        }

        pub fn format(self: *const HINFO, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print("CPU: \"{s}\", OS: \"{s}\"", .{ self.cpu, self.os });
        }

        pub fn decompress(self: HINFO, allocator: mem.Allocator, _: []const u8) !HINFO {
            const cpu = try allocator.dupe(u8, self.cpu);
            errdefer allocator.free(cpu);
            const os = try allocator.dupe(u8, self.os);
            return .{
                .allocator = allocator,
                .cpu = cpu,
                .os = os,
            };
        }
    };

    pub const MB = struct {
        /// A domain name which specifies a host which has the specified
        /// mailbox.
        madname: DomainName,

        pub fn to_writer(self: *const MB, writer: anytype) !void {
            try self.madname.to_writer(writer);
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, _: u16) !MB {
            return .{
                .madname = try DomainName.from_reader(allocator, reader),
            };
        }

        pub fn deinit(self: *const MB) void {
            self.madname.deinit();
        }

        pub fn format(self: *const MB, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print("{}", .{self.madname});
        }

        pub fn decompress(self: MB, allocator: mem.Allocator, packet: []const u8) !MB {
            return .{
                .madname = try self.madname.decompress(allocator, packet),
            };
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

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, _: u16) !MD {
            return .{
                .madname = try DomainName.from_reader(allocator, reader),
            };
        }

        pub fn deinit(self: *const MD) void {
            self.madname.deinit();
        }

        pub fn format(self: *const MD, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print("{}", .{self.madname});
        }

        pub fn decompress(self: MD, allocator: mem.Allocator, packet: []const u8) !MD {
            return .{
                .madname = try self.madname.decompress(allocator, packet),
            };
        }
    };

    pub const MF = struct {
        /// A domain name which specifies a host which has a mail agent
        /// for the domain which will accept mail for forwarding to the
        /// domain.
        madname: DomainName,

        pub fn to_writer(self: *const MF, writer: anytype) !void {
            try self.madname.to_writer(writer);
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, _: u16) !MF {
            return .{
                .madname = try DomainName.from_reader(allocator, reader),
            };
        }

        pub fn deinit(self: *const MF) void {
            self.madname.deinit();
        }

        pub fn format(self: *const MF, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print("{}", .{self.madname});
        }

        pub fn decompress(self: MF, allocator: mem.Allocator, packet: []const u8) !MF {
            return .{
                .madname = try self.madname.decompress(allocator, packet),
            };
        }
    };

    pub const MG = struct {
        /// A domain name which specifies a mailbox which is a member of
        /// the mail group specified by the domain name.
        madname: DomainName,

        pub fn to_writer(self: *const MG, writer: anytype) !void {
            try self.madname.to_writer(writer);
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, _: u16) !MG {
            return .{
                .madname = try DomainName.from_reader(allocator, reader),
            };
        }

        pub fn deinit(self: *const MG) void {
            self.madname.deinit();
        }

        pub fn format(self: *const MG, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print("{}", .{self.madname});
        }

        pub fn decompress(self: MG, allocator: mem.Allocator, packet: []const u8) !MG {
            return .{
                .madname = try self.madname.decompress(allocator, packet),
            };
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

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, _: u16) !MINFO {
            return .{
                .rmailbx = try DomainName.from_reader(allocator, reader),
                .emailbx = try DomainName.from_reader(allocator, reader),
            };
        }

        pub fn deinit(self: *const MINFO) void {
            self.rmailbx.deinit();
            self.emailbx.deinit();
        }

        pub fn format(self: *const MINFO, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print("rmailbox: {}, emailbox: {}", .{ self.rmailbx, self.emailbx });
        }

        pub fn decompress(self: MINFO, allocator: mem.Allocator, packet: []const u8) !MINFO {
            const rmailbx = try self.rmailbx.decompress(allocator, packet);
            errdefer rmailbx.deinit();
            const emailbx = try self.emailbx.decompress(allocator, packet);
            return .{
                .rmailbx = rmailbx,
                .emailbx = emailbx,
            };
        }
    };

    pub const MR = struct {
        /// A domain name which specifies a mailbox which is the proper
        /// rename of the specified mailbox.
        madname: DomainName,

        pub fn to_writer(self: *const MR, writer: anytype) !void {
            try self.madname.to_writer(writer);
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, _: u16) !MR {
            return .{
                .madname = try DomainName.from_reader(allocator, reader),
            };
        }

        pub fn deinit(self: *const MR) void {
            self.madname.deinit();
        }

        pub fn format(self: *const MR, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print("{}", .{self.madname});
        }

        pub fn decompress(self: MR, allocator: mem.Allocator, packet: []const u8) !MR {
            return .{
                .madname = try self.madname.decompress(allocator, packet),
            };
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
            try writer.writeInt(u16, self.preference, .big);
            try self.exchange.to_writer(writer);
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, _: u16) !MX {
            return .{
                .preference = try reader.readInt(u16, .big),
                .exchange = try DomainName.from_reader(allocator, reader),
            };
        }

        pub fn deinit(self: *const MX) void {
            self.exchange.deinit();
        }

        pub fn format(self: *const MX, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print("Preference: {d}, Exchange: {}", .{ self.preference, self.exchange });
        }

        pub fn decompress(self: MX, allocator: mem.Allocator, packet: []const u8) !MX {
            return .{
                .preference = self.preference,
                .exchange = try self.exchange.decompress(allocator, packet),
            };
        }
    };

    pub const NULL = struct {
        allocator: mem.Allocator,
        data: []const u8,

        pub fn to_writer(self: *const NULL, writer: anytype) !void {
            try writer.writeAll(self.data);
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, size: u16) !NULL {
            const data = try allocator.alloc(u8, size);
            errdefer allocator.free(data);
            const len = try reader.readAll(data);
            if (len < size) {
                return error.EndOfStream;
            }
            return .{
                .allocator = allocator,
                .data = data,
            };
        }

        pub fn deinit(self: *const NULL) void {
            self.allocator.free(self.data);
        }

        pub fn format(self: *const NULL, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print("{s}", .{std.fmt.fmtSliceHexUpper(self.data)});
        }

        pub fn decompress(self: NULL, allocator: mem.Allocator, _: []const u8) !NULL {
            return .{
                .allocator = allocator,
                .data = try allocator.dupe(u8, self.data),
            };
        }
    };

    pub const NS = struct {
        /// A domain name which specifies a host which should be
        /// authoritative for the specified class and domain.
        nsdname: DomainName,

        pub fn to_writer(self: *const NS, writer: anytype) !void {
            try self.nsdname.to_writer(writer);
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, _: u16) !NS {
            return .{
                .nsdname = try DomainName.from_reader(allocator, reader),
            };
        }

        pub fn deinit(self: *const NS) void {
            self.nsdname.deinit();
        }

        pub fn format(self: *const NS, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print("{}", .{self.nsdname});
        }

        pub fn decompress(self: NS, allocator: mem.Allocator, packet: []const u8) !NS {
            return .{
                .nsdname = try self.nsdname.decompress(allocator, packet),
            };
        }
    };

    pub const PTR = struct {
        /// A domain name which points to some location in the domain name
        /// space.
        ptrdname: DomainName,

        pub fn to_writer(self: *const PTR, writer: anytype) !void {
            try self.ptrdname.to_writer(writer);
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, _: u16) !PTR {
            return .{
                .ptrdname = try DomainName.from_reader(allocator, reader),
            };
        }

        pub fn deinit(self: *const PTR) void {
            self.ptrdname.deinit();
        }

        pub fn format(self: *const PTR, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print("{}", .{self.ptrdname});
        }

        pub fn decompress(self: PTR, allocator: mem.Allocator, packet: []const u8) !PTR {
            return .{
                .ptrdname = try self.ptrdname.decompress(allocator, packet),
            };
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

        pub fn to_writer(self: *const SOA, writer: anytype) !void {
            try self.mname.to_writer(writer);
            try self.rname.to_writer(writer);
            try writer.writeInt(u32, self.serial, .big);
            try writer.writeInt(i32, self.refresh, .big);
            try writer.writeInt(i32, self.retry, .big);
            try writer.writeInt(i32, self.expire, .big);
            try writer.writeInt(u32, self.minimum, .big);
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, _: u16) !SOA {
            return .{
                .mname = try DomainName.from_reader(allocator, reader),
                .rname = try DomainName.from_reader(allocator, reader),
                .serial = try reader.readInt(u32, .big),
                .refresh = try reader.readInt(i32, .big),
                .retry = try reader.readInt(i32, .big),
                .expire = try reader.readInt(i32, .big),
                .minimum = try reader.readInt(u32, .big),
            };
        }

        pub fn deinit(self: *const SOA) void {
            self.mname.deinit();
            self.rname.deinit();
        }

        pub fn format(self: *const SOA, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print(
                \\SOA {{
                \\        Primary Nameserver: {}
                \\        Responsible Person Mailbox: {}
                \\        Version Serial: {d}
                \\        Refresh: {d}
                \\        Retry: {d}
                \\        Expire: {d}
                \\        Minumum: {d}
                \\      }}
            , .{ self.mname, self.rname, self.serial, self.refresh, self.retry, self.expire, self.minimum });
        }

        pub fn decompress(self: SOA, allocator: mem.Allocator, packet: []const u8) !SOA {
            const mname = try self.mname.decompress(allocator, packet);
            const rname = try self.rname.decompress(allocator, packet);
            return .{
                .mname = mname,
                .rname = rname,
                .serial = self.serial,
                .refresh = self.refresh,
                .retry = self.retry,
                .expire = self.expire,
                .minimum = self.minimum,
            };
        }
    };

    pub const TXT = struct {
        allocator: mem.Allocator,
        /// One or more strings.
        txt_data: [][]const u8,

        pub fn to_writer(self: *const TXT, writer: anytype) !void {
            for (self.txt_data) |txt| {
                if (txt.len > 255) {
                    return error.TxtTooLong;
                }
                try writer.writeByte(@intCast(txt.len));
                try writer.writeAll(txt);
            }
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, size: u16) !TXT {
            var txt_data = StrList.init(allocator);

            errdefer {
                for (txt_data.items) |txt| {
                    allocator.free(txt);
                }
                txt_data.deinit();
            }

            var bytes_read: usize = 0;
            while (bytes_read < size) {
                const txt = try allocator.alloc(u8, try reader.readByte());
                errdefer allocator.free(txt);
                const txt_len = try reader.readAll(txt);
                if (txt_len < txt.len) {
                    return error.EndOfStream;
                }
                try txt_data.append(txt);
                bytes_read += txt_len + 1;
            }
            return .{
                .allocator = allocator,
                .txt_data = try txt_data.toOwnedSlice(),
            };
        }

        pub fn deinit(self: *const TXT) void {
            for (self.txt_data) |txt| {
                self.allocator.free(txt);
            }
            self.allocator.free(self.txt_data);
        }

        pub fn format(self: *const TXT, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
            _ = fmt;
            _ = options;
            for (self.txt_data) |txt| {
                try writer.print("\"{s}\"", .{txt});
            }
        }

        pub fn decompress(self: TXT, allocator: mem.Allocator, _: []const u8) !TXT {
            var str_list = StrList.init(allocator);

            errdefer {
                for (str_list.items) |txt| {
                    allocator.free(txt);
                }
                str_list.deinit();
            }

            for (self.txt_data) |txt| {
                try str_list.append(try allocator.dupe(u8, txt));
            }
            return .{
                .allocator = allocator,
                .txt_data = try str_list.toOwnedSlice(),
            };
        }
    };

    pub const A = struct {
        /// An internet address
        address: [4]u8,

        pub fn to_writer(self: *const A, writer: anytype) !void {
            try writer.writeAll(&self.address);
        }

        pub fn from_reader(_: mem.Allocator, reader: anytype, _: u16) !A {
            var address = [4]u8{ 0, 0, 0, 0 };
            const len = try reader.readAll(&address);
            if (len < 4) {
                return error.EndOfStream;
            }
            return .{
                .address = address,
            };
        }

        pub fn deinit(_: *const A) void {}

        pub fn format(self: *const A, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
            _ = fmt;
            _ = options;
            try writer.print("{d}.{d}.{d}.{d}", .{ self.address[0], self.address[1], self.address[2], self.address[3] });
        }

        pub fn decompress(self: A, _: mem.Allocator, _: []const u8) !A {
            return self;
        }
    };

    pub const WKS = struct {
        allocator: mem.Allocator,
        /// An internet address
        address: [4]u8,
        /// An IP protocol number
        protocol: u8,
        /// A variable length bit map.
        bit_map: []const u8,

        pub fn to_writer(self: *const WKS, writer: anytype) !void {
            try writer.writeAll(&self.address);
            try writer.writeByte(self.protocol);
            try writer.writeAll(self.bit_map);
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, size: u16) !WKS {
            var address = [4]u8{ 0, 0, 0, 0 };
            const addr_len = try reader.readAll(&address);
            if (addr_len < size) {
                return error.EndOfStream;
            }
            const protocol = try reader.readByte();
            const bit_map = try allocator.alloc(u8, size - 5);
            errdefer allocator.free(bit_map);
            const bm_len = try reader.readAll(bit_map);
            if (bm_len + 5 < size) {
                return error.EndOfStream;
            }
            return .{
                .allocator = allocator,
                .address = address,
                .protocol = protocol,
                .bit_map = bit_map,
            };
        }

        pub fn deinit(self: *const WKS) void {
            self.allocator.free(self.bit_map);
        }

        pub fn format(self: *const WKS, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print("Address: {d}.{d}.{d}.{d}, Protocol: {d}, Bitmap: {s}", .{ self.address[0], self.address[1], self.address[2], self.address[3], self.protocol, std.fmt.fmtSliceEscapeUpper(self.bit_map) });
        }

        pub fn decompress(self: WKS, allocator: mem.Allocator, _: []const u8) !WKS {
            return .{
                .allocator = allocator,
                .address = self.address,
                .protocol = self.protocol,
                .bit_map = try allocator.dupe(u8, self.bit_map),
            };
        }
    };

    pub const Unknown = struct {
        allocator: mem.Allocator,
        data: []const u8,

        pub fn to_writer(self: *const Unknown, writer: anytype) !void {
            try writer.writeAll(self.data);
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, size: u16) !Unknown {
            const data = try allocator.alloc(u8, size);
            errdefer allocator.free(data);
            const len = try reader.readAll(data);
            if (len < size) {
                return error.EndOfStream;
            }
            return .{
                .allocator = allocator,
                .data = data,
            };
        }

        pub fn deinit(self: *const Unknown) void {
            self.allocator.free(self.data);
        }

        pub fn format(self: *const Unknown, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print("{s}", .{std.fmt.fmtSliceEscapeUpper(self.data)});
        }

        pub fn decompress(self: Unknown, allocator: mem.Allocator, _: []const u8) !Unknown {
            return .{
                .allocator = allocator,
                .data = try allocator.dupe(u8, self.data),
            };
        }
    };

    pub const RP = struct {
        allocator: mem.Allocator,
        /// A domain name that specifies the mailbox for the
        /// responsible person
        mbox_dname: DomainName,
        /// A domain name for which TXT RR's exist. A subsequent query
        /// can be performed to retrieve the associated TXT resource
        /// records at txt_dname.
        txt_dname: []const u8,

        pub fn to_writer(self: *const RP, writer: anytype) !void {
            try self.mbox_dname.to_writer(writer);
            try writer.writeAll(self.txt_dname);
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, size: u16) !RP {
            var counting_reader = io.countingReader(reader);
            const mbox = try DomainName.from_reader(allocator, counting_reader.reader());
            const txt = try allocator.alloc(u8, size - @as(u16, @intCast(counting_reader.bytes_read)));
            errdefer allocator.free(txt);
            const txt_length = try reader.readAll(txt);
            if (txt_length + counting_reader.bytes_read < size) {
                return error.EndOfStream;
            }
            return .{
                .allocator = allocator,
                .mbox_dname = mbox,
                .txt_dname = txt,
            };
        }

        pub fn deinit(self: *const RP) void {
            self.allocator.free(self.txt_dname);
            self.mbox_dname.deinit();
        }

        pub fn decompress(self: RP, allocator: mem.Allocator, packet: []const u8) !RP {
            const mbox_dname = try self.mbox_dname.decompress(allocator, packet);
            errdefer mbox_dname.deinit();
            const txt_dname = try allocator.dupe(u8, self.txt_dname);
            return .{
                .allocator = allocator,
                .mbox_dname = mbox_dname,
                .txt_dname = txt_dname,
            };
        }
    };

    pub const AAAA = struct {
        address: [16]u8,

        pub fn to_writer(self: *const AAAA, writer: anytype) !void {
            try writer.writeAll(&self.address);
        }

        pub fn from_reader(_: mem.Allocator, reader: anytype, _: u16) !AAAA {
            var address: [16]u8 = undefined;
            const length = try reader.readAll(&address);
            if (length < 16) {
                return error.EndOfStream;
            }
            return .{
                .address = address,
            };
        }

        pub fn deinit(_: *const AAAA) void {}

        pub fn format(self: *const AAAA, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
            _ = fmt;
            _ = options;
            try writer.print("{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
                self.address[0],
                self.address[1],
                self.address[2],
                self.address[3],
                self.address[4],
                self.address[5],
                self.address[6],
                self.address[7],
                self.address[8],
                self.address[9],
                self.address[10],
                self.address[11],
                self.address[12],
                self.address[13],
                self.address[14],
                self.address[15],
            });
        }

        pub fn decompress(self: AAAA, _: mem.Allocator, _: []const u8) !AAAA {
            return self;
        }
    };

    pub const SRV = struct {
        /// The priority of this target host. A client MUST attempt to
        /// contact the target host with the lowest-numbered priority
        /// it can reach
        priority: u16,
        /// A relative weight for entries with the same priority.
        /// Larger weights SHOULD be given a proportionately higher
        /// probability of being selected.
        weight: u16,
        /// The port on this target host of this service.
        port: u16,
        /// The domain name of the target host.
        target: DomainName,

        pub fn to_writer(self: *const SRV, writer: anytype) !void {
            try writer.writeInt(u16, self.priority, .big);
            try writer.writeInt(u16, self.weight, .big);
            try writer.writeInt(u16, self.port, .big);
            try self.target.to_writer(writer);
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, _: u16) !SRV {
            const priority = try reader.readInt(u16, .big);
            const weight = try reader.readInt(u16, .big);
            const port = try reader.readInt(u16, .big);
            const target = try DomainName.from_reader(allocator, reader);

            return .{
                .priority = priority,
                .weight = weight,
                .port = port,
                .target = target,
            };
        }

        pub fn deinit(self: *const SRV) void {
            self.target.deinit();
        }

        pub fn format(self: *const SRV, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print(
                \\SRV {{
                \\        Priority: {d}
                \\        Weight: {d}
                \\        Port: {d}
                \\        Target: {}
                \\      }}
            , .{ self.priority, self.weight, self.port, self.target });
        }

        pub fn decompress(self: SRV, allocator: mem.Allocator, packet: []const u8) !SRV {
            return .{
                .priority = self.priority,
                .weight = self.weight,
                .port = self.port,
                .target = try self.target.decompress(allocator, packet),
            };
        }
    };

    pub const SSHFP = struct {
        allocator: mem.Allocator,
        /// The algorithm of the public key.
        algorithm: Algorithm,
        /// The message-digest algorithm used to calculate the
        /// fingerprint of the public key.
        fingerprint_type: FingerprintType,
        /// Hexadecimal representation of the hash result, as text.
        fingerprint: []const u8,

        const Algorithm = enum(u8) {
            RSA = 1,
            DSA = 2,
            ECDSA = 3,
            Ed25519 = 4,
            Ed448 = 5,
        };

        const FingerprintType = enum(u8) {
            SHA1 = 1,
            SHA256 = 2,
        };

        pub fn to_writer(self: *const SSHFP, writer: anytype) !void {
            try writer.writeByte(@intFromEnum(self.algorithm));
            try writer.writeByte(@intFromEnum(self.fingerprint_type));
            try writer.writeAll(self.fingerprint);
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, size: u16) !SSHFP {
            const algorithm: Algorithm = @enumFromInt(try reader.readByte());
            const fingerprint_type: FingerprintType = @enumFromInt(try reader.readByte());
            const fingerprint = try allocator.alloc(u8, size - 2);
            errdefer allocator.free(fingerprint);
            const length = try reader.readAll(fingerprint);
            if (length + 2 < size) {
                return error.EndOfStream;
            }

            return .{
                .allocator = allocator,
                .algorithm = algorithm,
                .fingerprint_type = fingerprint_type,
                .fingerprint = fingerprint,
            };
        }

        pub fn deinit(self: *const SSHFP) void {
            self.allocator.free(self.fingerprint);
        }

        pub fn format(self: *const SSHFP, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print("Algorithm: {s}, Fingerprint Type: {s}, Fingerprint: {s}", .{ @tagName(self.algorithm), @tagName(self.fingerprint_type), self.fingerprint });
        }

        pub fn decompress(self: SSHFP, allocator: mem.Allocator, _: []const u8) !SSHFP {
            return .{
                .allocator = allocator,
                .algorithm = self.algorithm,
                .fingerprint_type = self.fingerprint_type,
                .fingerprint = try allocator.dupe(u8, self.fingerprint),
            };
        }
    };

    pub const URI = struct {
        allocator: mem.Allocator,
        /// The priority of this target host. A client MUST attempt to
        /// contact the target host with the lowest-numbered priority
        /// it can reach
        priority: u16,
        /// A relative weight for entries with the same priority.
        /// Larger weights SHOULD be given a proportionately higher
        /// probability of being selected.
        weight: u16,
        /// This field holds the URI of the target, enclosed in
        /// double-quote characters ('"'), where the URI is as
        /// specified in RFC 3986.
        target: []const u8,

        pub fn to_writer(self: *const URI, writer: anytype) !void {
            try writer.writeInt(u16, self.priority, .big);
            try writer.writeInt(u16, self.weight, .big);
            try writer.writeAll(self.target);
        }

        pub fn from_reader(allocator: mem.Allocator, reader: anytype, size: u16) !URI {
            const priority = try reader.readInt(u16, .big);
            const weight = try reader.readInt(u16, .big);
            const target = allocator.alloc(u8, size - 4);
            errdefer allocator.free(target);
            const length = try reader.readAll(target);
            if (length + 4 < size) {
                return error.EndOfStream;
            }

            return .{
                .allocator = allocator,
                .priority = priority,
                .weight = weight,
                .target = target,
            };
        }

        pub fn deinit(self: *const URI) void {
            self.allocator.free(self.target);
        }

        pub fn format(self: *const URI, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print("Priority: {d}, Weight: {d}, Target: {s}", .{ self.priority, self.weight, self.target });
        }

        pub fn decompress(self: URI, allocator: mem.Allocator, _: []const u8) !URI {
            return .{
                .allocator = allocator,
                .priority = self.priority,
                .weight = self.weight,
                .target = try allocator.dupe(u8, self.target),
            };
        }
    };

    pub const LOC = struct {
        /// Version number of the representation. This must be zero.
        version: u8 = 0,
        /// The diameter of a sphere enclosing the described entity,
        /// in centimeters.
        ///
        /// Default = 1m
        size: PrecisionSize = .{ .base = 1, .power = 2 },
        /// The horizontal precision of the data, in centimeters.
        /// This is the diameter of the horizontal "circle of error",
        /// rather than a "plus or minus" value. To get a "plus or
        /// minus" value, divide by 2.
        ///
        /// Default = 10km
        horizontal_precision: PrecisionSize = .{ .base = 1, .power = 6 },
        /// The vertical precision of the data, in centimeters.
        /// This is the total potential vertical error, rather than a
        /// "plus or minus" value. To get a "plus or minus" value,
        /// divide by 2. Note that if altitude above or below sea
        /// level is used as an approximation for altitude relative to
        /// the [WGS 84] ellipsoid, the precision value should be
        /// adjusted.
        ///
        /// Default = 10m
        vertical_precision: PrecisionSize = .{ .base = 1, .power = 3 },
        /// The latitude of the center of the sphere described by the
        /// size field, in thousandths of a second of arc. 2^31
        /// represents the equator; numbers above that are north
        /// latitude.
        latitude: u32,
        /// The longitude of the center of the sphere described by the
        /// size field, in thousandths of a second of arc, rounded
        /// away from the prime meridian. 2^31 represents the prime
        /// meridian; numbers above that are east longitude.
        longitude: u32,
        /// The altitude of the center of the sphere described by the
        /// size field, in centimeters, from a base of 100,000m below
        /// the [WGS 84] reference spheroid used by GPS (semimajor
        /// axis a=6378137.0, reciprocal flattening rf=298.257223563).
        /// Altitude above (or below) sea level may be used as an
        /// approximation of altitude relative to the the [WGS 84]
        /// spheroid, though due to the Earth's surface not being a
        /// perfect spheroid, there will be differences. (For example,
        /// the geoid (which sea level approximates) for the
        /// continental US ranges from 10 meters to 50 meters below
        /// the [WGS 84] spheroid. Adjustments to altitude and/or
        /// vertical precision will be necessary in most cases. The
        /// Defense Mapping Agency publishes geoid height values
        /// relative to the [WGS 84] ellipsoid.
        altitude: u32,

        pub const PrecisionSize = packed struct(u8) {
            /// The power of ten by which to multiply the base.
            power: u4,
            base: u4,

            pub fn from_int(n: u32) PrecisionSize {
                const power = std.math.log10(n);
                const base = n / std.math.pow(u32, 10, power);

                return .{
                    .power = @intCast(power),
                    .base = @intCast(base),
                };
            }

            pub fn to_int(self: *const PrecisionSize) u32 {
                return self.base * (std.math.pow(u32, 10, self.power));
            }
        };

        pub const LatLong = struct {
            degrees: u8,
            minutes: u8,
            seconds: u8,
            fraction_seconds: u32,
            direction: Direction,

            const Direction = enum {
                North,
                East,
                South,
                West,
            };
        };

        pub const reference_altitude = 100_000 * 100;

        pub fn getLatitude(self: *const LOC) LatLong {
            var latitude = self.latitude - (1 << 31);
            var direction: LatLong.Direction = undefined;
            if (latitude < 0) {
                latitude = -latitude;
                direction = .South;
            } else {
                direction = .North;
            }
            const fraction_seconds = latitude % 1000;
            latitude /= 1000;
            const seconds = latitude % 60;
            latitude /= 60;
            const minutes = latitude % 60;
            latitude /= 60;
            const degrees = latitude;

            return .{
                .degrees = @intCast(degrees),
                .minutes = @intCast(minutes),
                .seconds = @intCast(seconds),
                .fraction_seconds = fraction_seconds,
                .direction = direction,
            };
        }

        pub fn getLongitude(self: *const LOC) LatLong {
            var longitude = self.longitude - (1 << 31);
            var direction: LatLong.Direction = undefined;
            if (longitude < 0) {
                longitude = -longitude;
                direction = .East;
            } else {
                direction = .West;
            }
            const fraction_seconds = longitude % 1000;
            longitude /= 1000;
            const seconds = longitude % 60;
            longitude /= 60;
            const minutes = longitude % 60;
            longitude /= 60;
            const degrees = longitude;

            return .{
                .degrees = @intCast(degrees),
                .minutes = @intCast(minutes),
                .seconds = @intCast(seconds),
                .fraction_seconds = fraction_seconds,
                .direction = direction,
            };
        }

        /// Relative to sea level / WGS 84, in centimeters
        pub fn getAltitude(self: *const LOC) i32 {
            return reference_altitude - @as(i32, @intCast(self.altitude));
        }

        pub fn to_writer(self: *const LOC, writer: anytype) !void {
            try writer.writeByte(self.version);
            try writer.writeByte(@bitCast(self.size));
            try writer.writeByte(@bitCast(self.horizontal_precision));
            try writer.writeByte(@bitCast(self.vertical_precision));
            try writer.writeInt(u32, self.latitude, .big);
            try writer.writeInt(u32, self.longitude, .big);
            try writer.writeInt(u32, self.altitude, .big);
        }

        pub fn from_reader(_: mem.Allocator, reader: anytype, _: u16) !LOC {
            const version = try reader.readByte();
            const size: PrecisionSize = @bitCast(try reader.readByte());
            const horizontal_precision: PrecisionSize = @bitCast(try reader.readByte());
            const vertical_prevision: PrecisionSize = @bitCast(try reader.readByte());
            const latitude = try reader.readInt(u32, .big);
            const longitude = try reader.readInt(u32, .big);
            const altitude = try reader.readInt(u32, .big);

            return .{
                .version = version,
                .size = size,
                .horizontal_precision = horizontal_precision,
                .vertical_precision = vertical_prevision,
                .latitude = latitude,
                .longitude = longitude,
                .altitude = altitude,
            };
        }

        pub fn deinit(_: *const LOC) void {}

        pub fn decompress(self: LOC, _: mem.Allocator, _: []const u8) !LOC {
            return self;
        }
    };
};

/// Helper for writing errdefer blocks
fn listDeinit(list: anytype) void {
    for (list.items) |item| {
        item.deinit();
    }
    list.deinit();
}

fn formatTagName(value: anytype, writer: anytype) !void {
    inline for (comptime std.enums.values(@TypeOf(value))) |val| {
        if (value == val) {
            try writer.print("{s}", .{@tagName(value)});
            return;
        }
    }
    try writer.print("{d}", .{@intFromEnum(value)});
}

test "ref all decls" {
    std.testing.refAllDeclsRecursive(@This());
}
