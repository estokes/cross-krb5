use bytes::Bytes;
use cross_krb5::{AcceptFlags, ClientCtx, InitiateFlags, K5Ctx, OrContinue, ServerCtx};
use std::{env::args, process::exit, sync::mpsc, thread};

enum Msg {
    Token(Bytes),
    Msg(Bytes),
}

fn server(spn: String, input: mpsc::Receiver<Msg>, output: mpsc::Sender<Msg>) {
    let mut server = ServerCtx::create(AcceptFlags::empty(), Some(&spn)).expect("create");
    let mut server = loop {
        let token = match input.recv().expect("expected data") {
            Msg::Msg(_) => panic!("server not finished initializing"),
            Msg::Token(t) => t,
        };
        match server.step(&*token).expect("step") {
            OrContinue::Finished((ctx, token)) => {
                if let Some(token) = token {
                    output.send(Msg::Token(Bytes::copy_from_slice(&*token))).expect("send");
                }
                break ctx
            },
            OrContinue::Continue((ctx, token)) => {
                output.send(Msg::Token(Bytes::copy_from_slice(&*token))).expect("send");
                server = ctx;
            }
        }
    };
    match input.recv().expect("expected data msg") {
        Msg::Token(_) => panic!("unexpected extra token"),
        Msg::Msg(secret_msg) => println!(
            "{}",
            String::from_utf8_lossy(&server.unwrap(&*secret_msg).expect("unwrap"))
        ),
    }
}

fn client(spn: &str, input: mpsc::Receiver<Msg>, output: mpsc::Sender<Msg>) {
    let (mut client, token) =
        ClientCtx::initiate(InitiateFlags::empty(), None, spn, None).expect("initiate");
    output.send(Msg::Token(Bytes::copy_from_slice(&*token))).expect("send");
    let mut client = loop {
        let token = match input.recv().expect("expected data") {
            Msg::Msg(_) => panic!("client not finished initializing"),
            Msg::Token(t) => t,
        };
        match client.step(&*token).expect("step") {
            OrContinue::Finished((ctx, token)) => {
                if let Some(token) = token {
                    output.send(Msg::Token(Bytes::copy_from_slice(&*token))).expect("send");
                }
                break ctx
            },
            OrContinue::Continue((ctx, token)) => {
                output.send(Msg::Token(Bytes::copy_from_slice(&*token))).expect("send");
                client = ctx;
            }
        }
    };
    let msg = client.wrap(true, b"super secret message").expect("wrap");
    output.send(Msg::Msg(Bytes::copy_from_slice(&*msg))).expect("send");
}

fn main() {
    let args = args().collect::<Vec<_>>();
    if args.len() != 2 {
        println!("usage: {}: <service/host@REALM>", args[0]);
        exit(1);
    }
    let spn = String::from(&args[1]);
    let (server_snd, server_recv) = mpsc::channel();
    let (client_snd, client_recv) = mpsc::channel();
    thread::spawn(move || server(spn, server_recv, client_snd));
    client(&args[1], client_recv, server_snd);
}
