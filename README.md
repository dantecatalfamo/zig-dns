# zig-dns

Experimental DNS library implemented in zig.

So far implements [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html) plus some updates.

### Features
  * Streaming interface
  * Parse DNS packets
  * Generate DNS packets
  * Print packet contents
  
### Interactive

For testing and development purposes you can call the library interactively from the command line.

```
Usage: zig-dns <dns-server> <domain> <query-type>
```

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

var message_bytes = try message.to_bytes();
try writer.writeAll(message_bytes);

var recv = [_]u8{0} ** 1024;
const recv_size = try sock.receive(&recv);

const response = try Message.from_bytes(recv[0..recv_size]);
defer response.deinit();

std.debug.print("Response: {any}\n", .{ response });
```

Output:

```
Response:
Message {
Header {
  ID: 1
  Response: true
  OpCode: query
  Authoritative Answer: false
  Truncation: false
  Recursion Desired: true
  Recursion Available: true
  Z: 0
  Response Code: no_error
}
Question {
  Name: lambda.cx.
  QType: A
  QClass: IN
}
Resource Record {
  Name: lambda.cx.
  Type: A
  Class: IN
  TTL: 1800
  Resource Data Length: 4
  Resource Data: 155.138.137.134
}
}
```
