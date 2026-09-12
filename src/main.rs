#![feature(seek_stream_len)]

use clap::Parser;
use fast_socks5::{
    ReplyError, Result, Socks5Command, SocksError, server::{DnsResolveHelper as _, Socks5ServerProtocol, states::CommandRead}, util::target_addr::{TargetAddr, ToTargetAddr}
};

use tracing::info;
use std::{future::Future, sync::Arc};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};
use tokio::task;
// use pretty_hex::PrettyHex;

use crate::{mitm::Mitm, mitm_gui::MitmGuiState, server::Server};

pub mod cipher;
pub mod protocol;
pub mod ptrace;
pub mod rqode_binrw;
pub mod server;
pub mod mitm;
pub mod mitm_gui;
pub mod packet_view;

#[derive(clap::ValueEnum, Clone, Copy)]
enum Mode {
    Server,
    Mitm
}

#[derive(clap::Parser)]
struct Cli {
    mode: Mode,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    
    spawn_socks_server().await
}

async fn spawn_socks_server() -> Result<()> {
    let args = Cli::parse();

    let listener = TcpListener::bind("127.0.0.1:8008").await?;

    info!("Listen for socks connections");

    let mode = match args.mode {
        Mode::Server => ServerMode::Server(Arc::new(Server::init())),
        Mode::Mitm => ServerMode::Mitm(mitm_gui::start()),
    };
    
    // Standard TCP loop
    loop {
        match listener.accept().await {
            Ok((socket, _client_addr)) => {
                println!("SOCKS connect from {_client_addr}");
                spawn_and_log_error(serve_socks5(socket, mode.clone()));
            }
            Err(err) => {
                println!("accept error = {:?}", err);
            }
        }
    }
}

#[derive(Clone)]
enum ServerMode {
    Server(Arc<Server>),
    Mitm(MitmGuiState),
}

async fn serve_socks5(socket: tokio::net::TcpStream, mode: ServerMode) -> Result<(), SocksError> {
    let (proto, cmd, target_addr) = Socks5ServerProtocol::accept_no_auth(socket).await?
        .read_command()
        .await?
        .resolve_dns()
        .await?;

    match cmd {
        Socks5Command::TCPConnect => {
            println!("Connect to {}", target_addr);
            match mode {
                ServerMode::Mitm(state) => {
                    spawn_and_log_error(do_mitm(proto, target_addr, state));
                },
                ServerMode::Server(s) => {
                    // Refuse connection to github ?..
                    if target_addr.clone().into_string_and_port().1 == 443 {
                        proto.reply_error(&ReplyError::ConnectionRefused).await?;
                        return Ok(());
                    }
                    let conn = proto.reply_success("127.0.0.1:0".parse().unwrap()).await?;
                    s.add_connection(conn);
                },
            };
        }
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

async fn do_mitm(
    proto: Socks5ServerProtocol<TcpStream, CommandRead>,
    addr: TargetAddr,
    state: MitmGuiState,
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

    let mut state = Mitm::new(false, state);

    loop {
        tokio::select! {
            read = sock.read(&mut rbuf) => {
                let len = read?;
                if len == 0 {
                    println!("read 0");
                    return Ok(());
                }

                // println!("<-- {ty}: {:#?}", &rbuf[..len].hex_dump());
                let data = state.process_server_data(&rbuf[..len])?;
                // tokio::time::sleep(Duration::from_millis(300)).await;
                // println!("<-- mitm: {:#?}", &data.hex_dump());
                if data.is_empty() {
                    continue;
                }
                
                socks.write_all(&data).await?;
            },
            read = socks.read(&mut wbuf) => {
                let len = read?;
                if len == 0 {
                    println!("write 0");
                    return Ok(());
                }
               
                // println!("--> {ty}: {:#?}", &wbuf[..len].hex_dump());
                let data = state.process_game_data(&wbuf[..len])?;
                // tokio::time::sleep(Duration::from_millis(300)).await;
                // println!("--> mitm: {:#?}", &data.hex_dump());

                if data.is_empty() {
                    continue;
                }

                sock.write_all(&data).await?;
            }
        }
    }
}
