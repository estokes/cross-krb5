use cross_krb5::{AcceptFlags, ClientCtx, InitiateFlags, K5Ctx, ServerCtx};
use std::{env::args, process::exit};

fn main() {
    let args = args().collect::<Vec<_>>();
    if args.len() != 2 {
        println!("usage: {}: <service/host@REALM>", args[0]);
        exit(1);
    }

    // make a pending context and a token to connect to `service/host@REALM`
    let (pending, token) =
        ClientCtx::initiate(InitiateFlags::empty(), None, &args[1], None)
            .expect("initiate");

    // accept the client's token for `service/host@REALM`. The token from the client
    // is accepted, and, if valid, the server end of the context and a token
    // for the client will be created.
    let (mut server, token) =
        ServerCtx::accept(AcceptFlags::empty(), Some("service/host@REALM"), &*token)
            .expect("accept");

    // use the server supplied token to finish initializing the pending client context.
    // Now encrypted communication between the two contexts is possible, and mutual
    // authentication has succeeded.
    let mut client = pending.finish(&*token).expect("finish");

    // send secret messages
    let secret_msg = client.wrap(true, b"super secret message").expect("wrap");
    println!(
        "{}",
        String::from_utf8_lossy(&server.unwrap(&*secret_msg).expect("unwrap"))
    );
}
