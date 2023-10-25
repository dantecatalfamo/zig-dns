const std = @import("std");
const mem = std.mem;
const debug = std.debug;
const testing = std.testing;
const dns = @import("dns.zig");
const network = @import("network");

const root_server = "a.root-servers.net";

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();
    try network.init();
    defer network.deinit();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next();
    const domain = args.next().?;
    const qtype = std.meta.stringToEnum(dns.QType, args.next() orelse "A") orelse .A;

    std.debug.print("querying: {s}\n", .{root_server});
    var query = try makeNonRecursiveQuery(allocator, root_server, domain, qtype);

    var resolved = false;
    while (!resolved) {
        if (query.answers.len != 0) {
            resolved = true;
        } else if (query.authorities.len != 0) {
            switch (query.authorities[0].resource_data) {
                .ns => {
                    const ns = try query.authorities[0].resource_data.ns.nsdname.to_string(allocator);
                    defer allocator.free(ns);
                    query.deinit();
                    std.debug.print("querying: {s}\n", .{ns});
                    query = try makeNonRecursiveQuery(allocator, ns, domain, qtype);
                },
                else => {
                    std.debug.print("No record found\n", .{});
                    query.deinit();
                    return;
                },
            }
        } else {
            std.debug.print("No record found\n", .{});
            query.deinit();
            return;
        }
    }

    for (query.answers) |answer| {
        std.debug.print("{}\n", .{answer.resource_data});
    }
    query.deinit();
}

pub fn makeNonRecursiveQuery(allocator: mem.Allocator, name_server: []const u8, domain: []const u8, query_type: dns.QType) !dns.Message {
    const sock = try network.connectToHost(allocator, name_server, 53, .udp);
    defer sock.close();
    const writer = sock.writer();

    var message = try dns.createQuery(allocator, domain, query_type);
    defer message.deinit();
    message.header.recursion_desired = false;

    var message_bytes = try message.to_bytes(allocator);
    defer allocator.free(message_bytes);

    try writer.writeAll(message_bytes);
    var recv = [_]u8{0} ** 2048;
    const recv_size = try sock.receive(&recv);
    const response_bytes = recv[0..recv_size];

    const response = try dns.Message.from_bytes(allocator, response_bytes);

    return response;
}
