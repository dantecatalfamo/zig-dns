const std = @import("std");

pub fn main() anyerror!void {
    std.log.info("All your codebase are belong to us.", .{});
}

const RR = struct {
    name: []const u8,
    @"type": RR_Type,
    class: RR_Class,
    ttl: i32,
    rd_length: u16,
    rdata: []const u8,
};


/// DNS Resource Record types
const RR_Type = enum (u16) {
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
const RR_Qtypes = enum (u16) {
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
const RR_Class = enum (u16) {
    /// The Internet
    IN = 1,
    /// The CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CS = 2,
    /// The CHAOS class
    CH = 3,
    /// Hesiod [Dyer 87]
    HS = 4,

    _,
};

/// QCLASS values are a superset of CLASS values; every CLASS is a valid QCLASS.
const RR_QClass = enum (u16) {
    /// Any Class
    @"*" = 255,
};
