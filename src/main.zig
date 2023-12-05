// Copyright (c) 2022 Dante Catalfamo
// SPDX-License-Identifier: MIT

const std = @import("std");
const network = @import("network");
const dns = @import("dns.zig");

pub fn usage() noreturn {
    std.debug.print("Usage: zig-dns <dns-server> <domain> <query-type>\n", .{});
    std.os.exit(1);
}

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();
    try network.init();
    defer network.deinit();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next();
    const dns_server = args.next() orelse usage();
    const domain = args.next() orelse usage();
    const query_type = args.next() orelse usage();

    const sock = try network.connectToHost(allocator, dns_server, 53, .udp);
    defer sock.close();
    const writer = sock.writer();

    const message = try dns.createQuery(allocator, domain, std.meta.stringToEnum(dns.QType, query_type) orelse usage());
    defer message.deinit();

    const message_bytes = try message.to_bytes(allocator);
    defer allocator.free(message_bytes);

    std.debug.print("Sending bytes: {any}\n", .{message_bytes});
    std.debug.print("Query:\n {}", .{message});

    try writer.writeAll(message_bytes);
    var recv = [_]u8{0} ** 1024;
    const recv_size = try sock.receive(&recv);
    const response_bytes = recv[0..recv_size];

    std.debug.print("Recv: {any}\n", .{response_bytes});
    const response = try dns.Message.from_bytes(allocator, response_bytes);
    defer response.deinit();
    std.debug.print("Response:\n{any}\n", .{response});
}
