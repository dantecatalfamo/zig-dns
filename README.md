# zig-dns

Experimental DNS library implemented in zig.

So far implements [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html) plus some updates.

The library itself has no dependencies, the CLI example uses [`zig-network`](https://github.com/MasterQ32/zig-network) to send and receive packets over the network.

* Library: `src/dns.zig`
* CLI test: `src/main.zig`

### Features
  * Streaming interface
  * Parse DNS packets
  * Generate DNS packets
  * Print packet contents
  * Label compression

### Currently supported record types

* A - A host address
* NS - An authoritative name server
* MD - A mail destination (Obsolete)
* MF - A mail forwarder (Obsolete)
* CNAME - The canonical name for an alias
* SOA - Marks the start of a zone of authority
* MB - A mailbox domain name (Experimental)
* MG - A mail group member (Experimental)
* MR - A mail rename domain name (Experimental)
* NULL - A byte array (Experimental)
* WKS - A well known service description
* PTR - A domain name pointer
* HINFO - Host information
* MINFO - Mailbox or mail list information
* MX - Mail exchange
* TXT - Text strings
* RP - Responsible Person [RFC 1183](https://www.rfc-editor.org/rfc/rfc1183)
* AAAA - An IPv6 host address [RFC 3596](https://www.rfc-editor.org/rfc/rfc3596)
* LOC - Location information [RFC 1876](https://datatracker.ietf.org/doc/html/rfc1876)
* SRV - Service locator [RFC 2782](https://www.rfc-editor.org/rfc/rfc2782)
* SSHFP - SSH Fingerprint [RFC 4255](https://www.rfc-editor.org/rfc/rfc4255), [RFC 6594](https://www.rfc-editor.org/rfc/rfc6594)
* URI - Uniform Resource Identifier [RFC 7553](https://www.rfc-editor.org/rfc/rfc7553.html)
  
### Interactive

For testing and development purposes you can call the library interactively from the command line.

```
Usage: zig-dns <dns-server> <domain> <query-type>
```

### Interactive Example

```
$ zig-dns 1.1.1.1 www.lambda.cx A
Sending bytes: { 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 119, 119, 119, 6, 108, 97, 109, 98, 100, 97, 2, 99, 120, 0, 0, 1, 0, 1 }
Query:
 Message {
  Header {
    ID: 1
    Response: false
    OpCode: query
    Authoritative Answer: false
    Truncation: false
    Recursion Desired: true
    Recursion Available: false
    Z: 0
    Response Code: no_error
  }
  Questions {
    Question {
      Name: www.lambda.cx.
      QType: A
      QClass: IN
    }
  }
  Ansewrs {
  }
  Authorities {
  }
  Additional {
  }
}
Recv: { 0, 1, 129, 128, 0, 1, 0, 2, 0, 0, 0, 0, 3, 119, 119, 119, 6, 108, 97, 109, 98, 100, 97, 2, 99, 120, 0, 0, 1, 0, 1, 192, 12, 0, 5, 0, 1, 0, 0, 7, 8, 0, 2, 192, 16, 192, 16, 0, 1, 0, 1, 0, 0, 7, 8, 0, 4, 155, 138, 137, 134 }
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
  Questions {
    Question {
      Name: www.lambda.cx.
      QType: A
      QClass: IN
    }
  }
  Ansewrs {
    Resource Record {
      Name: www.lambda.cx.
      Type: CNAME
      Class: IN
      TTL: 1800
      Resource Data Length: 2
      Resource Data: lambda.cx.
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
  Authorities {
  }
  Additional {
  }
}
```

### Example Code

```zig
const std = @import("std");
const io = std.io;
const network = @import("network");
const dns = @import("zig-dns/src/dns.zig");

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

std.debug.print("Response:\n{any}\n", .{ response });
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
  Questions {
    Question {
      Name: www.lambda.cx.
      QType: A
      QClass: IN
    }
  }
  Ansewrs {
    Resource Record {
      Name: www.lambda.cx.
      Type: CNAME
      Class: IN
      TTL: 1800
      Resource Data Length: 2
      Resource Data: lambda.cx.
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
  Authorities {
  }
  Additional {
  }
}
```

### Iterative Example
See [iterative.zig](src/iterative.zig) as an example for how to use this library iteratively.
