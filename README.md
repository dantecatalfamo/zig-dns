# zig-dns

Experimental DNS library implemented in zig.

So far implements [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html) plus some updates.

### Features
  * Streaming interface
  * Parse DNS packets
  * Generate DNS packets
  * Print packet contents
  
### Example

```zig
const std = @import("std");
const io = std.io;
const network = @import("network");
const dns = @import("zig-dns/src/main.zig");

// [...] Main function, allocator, etc.

try network.init();
defer network.deinit();
const sock = try network.connectToHost(allocator, "8.8.8.8", 53, .udp);
defer sock.close();
const writer = sock.writer();

const message = try dns.createQuery(allocator, "lambda.cx", .A);
defer message.deinit();

var message_bytes = std.ArrayList(u8).init(allocator);
defer message_bytes.deinit();

try message.to_writer(message_bytes.writer());
try writer.writeAll(message_bytes.items);

var recv = [_]u8{0} ** 1024;
const recv_size = try sock.receive(&recv);

var recv_buffer = std.io.fixedBufferStream(recv[0..recv_size]);
const response = try Message.from_reader(allocator, recv_buffer.reader());
defer response.deinit();

std.debug.print("Response: {any}\n", .{ response });
```

Output:

```
Response: Message {
Header {
  ID: 1
  Response: true
  OpCode: query
  Authoritative Answer: false
  Truncation: false
  Recursion Desired: true
  Recursion Available: true
  Z: 0
  Response no_error
}
Question {
  Name: lambda.cx.
  QType: A
  QClass: IN
}
Resource Record {
  Name: Pointer<12>
  Type: A
  Class: IN
  TTL: 1800
  Resource Data Length: 4
  Resource Data: 155.138.137.134
}
}
```
