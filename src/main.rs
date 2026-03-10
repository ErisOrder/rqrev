
use anyhow::Context;
use fast_socks5::{
    ReplyError, Result, Socks5Command, SocksError, server::{DnsResolveHelper as _, Socks5ServerProtocol, run_tcp_proxy, run_udp_proxy, states::CommandRead}, util::target_addr::TargetAddr
};
use std::{future::Future, num::ParseFloatError, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};
use tokio::task;
use pretty_hex::PrettyHex;

use crate::cipher::CipherState;

pub mod cipher;

#[tokio::main]
async fn main() -> Result<()> {
    spawn_socks_server().await
}

async fn spawn_socks_server() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8008").await?;

    println!("Listen for socks connections");

    // Standard TCP loop
    loop {
        match listener.accept().await {
            Ok((socket, _client_addr)) => {
                println!("SOCKS connect from {_client_addr}");
                spawn_and_log_error(serve_socks5(socket));
            }
            Err(err) => {
                println!("accept error = {:?}", err);
            }
        }
    }
}

async fn serve_socks5(socket: tokio::net::TcpStream) -> Result<(), SocksError> {
    let (proto, cmd, target_addr) = Socks5ServerProtocol::accept_no_auth(socket).await?
        .read_command()
        .await?
        .resolve_dns()
        .await?;

    match cmd {
        Socks5Command::TCPConnect => {
            println!("Connect to {}", target_addr);
            spawn_and_log_error(serve_tcp(proto, target_addr));
            // run_tcp_proxy(proto, &target_addr, Duration::from_secs(60), false).await?;
        }
        // Socks5Command::UDPAssociate if opt.allow_udp => {
        //     let reply_ip = opt.public_addr.context("invalid reply ip")?;
        //     run_udp_proxy(proto, &target_addr, None, reply_ip, None).await?;
        // }
        _ => {
            proto.reply_error(&ReplyError::CommandNotSupported).await?;
            return Err(ReplyError::CommandNotSupported.into());
        }
    };
    Ok(())
}

fn spawn_and_log_error<F>(fut: F) -> task::JoinHandle<()>
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    task::spawn(async move {
        match fut.await {
            Ok(()) => {}
            Err(err) => println!("{:#}", &err),
        }
    })
}

async fn serve_tcp(
    proto: Socks5ServerProtocol<TcpStream, CommandRead>,
    addr: TargetAddr,
) -> Result<()> {
    let addr = addr.into_string_and_port();
    let port = addr.1;
    
    // Connect to actual server
    let mut sock = TcpStream::connect(addr)
        .await?;

    let mut socks = proto.reply_success("127.0.0.1:0".parse().unwrap()).await?;
    
    // Decide server type by port
    let ty = match port {
        8080 => {
            "logn".to_string()
        },
        4254 => {
            "main".to_string()
        }
        other => {
            other.to_string()
        }
    };

    let mut rbuf = vec![0; 0xFFFF];
    let mut wbuf = vec![0; 0xFFFF];

    let mut state = CipherState::Uninit;

    loop {
        tokio::select! {
            read = sock.read(&mut rbuf) => {
                let mut len = read?;
                if len == 0 {
                    println!("read 0");
                    return Ok(());
                }

                println!("<-- {ty}: {:#?}", &rbuf[..len].hex_dump());

                match &state {
                    CipherState::ClientHandshakeReceived(mitm) => {
                        if len == 640 {
                            let raw = mitm.decode_handshake(&mut rbuf[..len]);
                            println!("<-- hand: {:#?}", raw.hex_dump());
                            // let data = mitm.encode_for_game(&raw);
                            // println!("<-- mitm: {:#?}", data.hex_dump());
                            // rbuf[..data.len()].copy_from_slice(&data);
                            // len = data.len();
                            state = CipherState::ServerHandshakeSent;
                        }
                    }
                    _ => (),
                }
                
                socks.write_all(&rbuf[..len]).await?;
            },
            read = socks.read(&mut wbuf) => {
                let len = read?;
                if len == 0 {
                    println!("write 0");
                    return Ok(());
                }
               
                println!("--> {ty}: {:#?}", &wbuf[..len].hex_dump());

                match &state {
                    CipherState::Uninit => {
                        if len == 132 {
                            let mitm = cipher::MitmRsa::new(&wbuf[..len]);
                            mitm.fill_pubk(&mut wbuf[..len]);
                            state = CipherState::ClientHandshakeReceived(mitm);
                            println!("--> mitm: {:#?}", &wbuf[..len].hex_dump());
                        }
                    }
                    CipherState::ServerHandshakeSent => {
                        state = CipherState::EncryptedChannel;
                    }
                    _ => (),
                }

                sock.write_all(&wbuf[..len]).await?;
            }
        }
    }
}
