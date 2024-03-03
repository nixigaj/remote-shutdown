use std::convert::Infallible;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use clap::Parser;
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{StatusCode};
use is_root::is_root;
use system_shutdown::{shutdown};
use tokio::fs;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Remote shutdown daemon
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// TcpListener bind string
    #[arg(short, long, required = true)]
    bind: String,

    /// Bcrypt hashed token enclosed in single tick quotes
    #[arg(short, long, required = true)]
    token: String,

    /// Ignore process not running as root
    #[arg(long)]
    ignore_not_root: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if !args.ignore_not_root && !is_root() {
        println!("Not running as root, use --ignore-not-root to bypass this");
        std::process::exit(1);
    }

    let addr: SocketAddr = args.bind.parse().unwrap();

    let make_svc = make_service_fn(move |_conn| {
        let token = Arc::new(args.token.clone());
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                server(req, token.clone())
            }))
        }
    });
    
    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on {}", addr);
    
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

async fn server(req: Request<Body>, token_hash: Arc<String>) -> Result<Response<Body>, Infallible> {
    let headers: &HeaderMap<HeaderValue> = req.headers();

    if let Some(token_header) = headers.get("token") {
        if let Ok(token_value) = token_header.to_str() {
            let hash = (*token_hash).clone();
            let parsed_hash = PasswordHash::new(hash.as_str()).unwrap();

            if !Argon2::default().verify_password(token_value.as_ref(), &parsed_hash).is_ok() {
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::from("Invalid token"))
                    .unwrap());
            }
            
            if req.uri().eq("/shutdown") {
                return match handle_shutdown().await {
                    Ok(()) => {
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .body(Body::from("Shutdown successful"))
                            .unwrap())
                    }
                    Err(err) => {
                        Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::from(format!("Shutdown failed: {}", err)))
                            .unwrap())
                    }
                }
            }

            if req.uri().eq("/lock") {
                return match handle_lock().await {
                    Ok(()) => {
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .body(Body::from("Session lock successful"))
                            .unwrap())
                    }
                    Err(err) => {
                        Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::from(format!("Session lock failed: {}", err)))
                            .unwrap())
                    }
                }
            }

            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Not found"))
                .unwrap())
        }
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Token header not valid format"))
            .unwrap());
    }
    Ok(Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(Body::from("Token header not found"))
        .unwrap())
}

async fn handle_shutdown() -> Result<(), String> {
    if is_systemd_running().await {
        let output = Command::new("poweroff")
            .output()
            .await
            .unwrap();

        if output.status.success() {
            return Ok(())
        }

        let mut file: File;

        match File::create("/proc/sysrq-trigger").await {
            Ok(f) => {file = f},
            Err(sysrq_error) => {
                return Err(
                    format!("'poweroff' command error: (exit code {}), and sysrq error ({})",
                            output.status, sysrq_error)
                )
            }
        }

        return match file.write_all(b"o").await {
            Ok(_) => {
                Ok(())
            },
            Err(sysrq_error) => {
                Err(format!("'poweroff' command error: (exit code {}), and sysrq error ({})",
                            output.status, sysrq_error))
            }
        }
    }
    match shutdown() {
        Ok(_) => {
            Ok(())
        },
        Err(error) => {
            if !cfg!(target_os = "linux") {
                return Err(format!("{}", error));
            }
    
            let mut file: File;
            
            match File::create("/proc/sysrq-trigger").await {
                Ok(f) => {file = f},
                Err(sysrq_error) => {
                    return Err(
                        format!("regular error: ({}), and sysrq error ({})", error, sysrq_error)
                    )
                }
            }
            
            match file.write_all(b"o").await {
                Ok(_) => {
                    Ok(())
                },
                Err(sysrq_error) => {
                    Err(format!("regular error: ({}), and sysrq error ({})", error, sysrq_error))
                } 
            }
        },
    }
}

async fn handle_lock() -> Result<(), String> {
    match Command::new("loginctl")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn() {
        Ok(_) => {},
        Err(_) => {
            return Err("Failed to find 'loginctl' command. \
            Support not implemented for other platform".to_string())
        },
    }
    
    let output = Command::new("loginctl")
        .arg("lock-session")
        .arg("-a")
        .output()
        .await
        .unwrap();

    return if output.status.success() {
        Ok(())
    } else {
        Err(format!("'loginctl' command error: (exit code {})", output.status))
    }
}

async fn is_systemd_running() -> bool {
    fs::metadata("/run/systemd/system").await.is_ok()
}
