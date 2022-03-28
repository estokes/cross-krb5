# Cross Platform Kerberos 5 Interface

cross-krb5 is a simplified and safe interface for basic Kerberos 5
services on Windows and Unix. It provides most of the
flexibility of using gssapi and sspi directly, but with the
reduced api complexity that comes from specifically targeting only
the Kerberos 5 mechanism.

As well as providing a uniform API, services using cross-krb5
should interoperate across all the supported OSes transparently,
and should interoperate with other services assuming they are not
platform specific.

# Example
```rust
use cross_krb5::{
    ClientCtx, 
    ServerCtx, 
    K5Ctx, 
    AcceptFlags, 
    InitiateFlags
};

// make a pending context and a token to connect to `service/host@REALM`
let (pending, token) = ClientCtx::initiate(
    InitiateFlags::empty(), 
    None, 
    "service/host@REALM",
    None
)?;

// accept the client's token for `service/host@REALM`. The token from the client
// is accepted, and, if valid, the server end of the context and a token
// for the client will be created.
let (mut server, token) = ServerCtx::accept(
    AcceptFlags::empty(), 
    Some("service/host@REALM"), &*token
)?;

// use the server supplied token to finish initializing the pending client context.
// Now encrypted communication between the two contexts is possible, and mutual
// authentication has succeeded.
let mut client = pending.finish(&*token)?;

// send secret messages
let secret_msg = client.wrap(true, b"super secret message")?;
println!("{}", String::from_utf8_lossy(&server.unwrap(&*secret_msg)?));

// ... profit!
```
