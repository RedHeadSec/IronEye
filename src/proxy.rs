use socks::{Socks4Stream, Socks5Stream};
use std::error::Error;
use std::net::TcpStream;
use url::Url;

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub enabled: bool,
    pub proxy_type: ProxyType,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProxyType {
    Socks4,
    Socks5,
}

pub fn handle_proxy_connection(
    proxy: Option<&ProxyConfig>,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, Box<dyn Error>> {
    if let Some(proxy_config) = proxy {
        println!(
            "[*] Connecting to target {} via proxy {}:{}",
            target_host, proxy_config.host, proxy_config.port
        );

        // Determine proxy type and establish connection
        let stream = match proxy_config.proxy_type {
            ProxyType::Socks5 => Socks5Stream::connect(
                (proxy_config.host.as_str(), proxy_config.port),
                (target_host, target_port),
            )
            .map_err(|e| format!("Failed to connect via SOCKS5 proxy: {}", e))?
            .into_inner(), // Extract the underlying TcpStream
            ProxyType::Socks4 => Socks4Stream::connect(
                (proxy_config.host.as_str(), proxy_config.port),
                (target_host, target_port),
                proxy_config.username.as_deref().unwrap_or(""), // Use username as userid or empty string
            )
            .map_err(|e| format!("Failed to connect via SOCKS4 proxy: {}", e))?
            .into_inner(), // Extract the underlying TcpStream
        };

        println!("[*] Proxy connection established successfully.");
        Ok(stream)
    } else {
        println!(
            "[*] No proxy specified. Connecting directly to {}:{}",
            target_host, target_port
        );
        let stream = TcpStream::connect((target_host, target_port))?;
        println!("[*] Direct connection established successfully.");
        Ok(stream)
    }
}

pub fn parse_proxy_url(proxy_url: &str) -> Result<ProxyConfig, String> {
    let url = Url::parse(proxy_url).map_err(|e| format!("Invalid URL: {}", e))?;

    // Extract and validate proxy type
    let proxy_type = match url.scheme().to_lowercase().as_str() {
        "socks4" => ProxyType::Socks4,
        "socks5" => ProxyType::Socks5,
        _ => return Err(format!("Unsupported proxy type: {}", url.scheme())),
    };

    // Extract host and port
    let host = url
        .host_str()
        .ok_or("Proxy URL must include a host")?
        .to_string();
    let port = url.port().ok_or("Proxy URL must include a port")?;

    // Extract username and password (if provided)
    let username = url.username().to_string();
    let username = if username.is_empty() {
        None
    } else {
        Some(username)
    };
    let password = url.password().map(|p| p.to_string());

    Ok(ProxyConfig {
        enabled: true,
        proxy_type,
        host,
        port,
        username,
        password,
    })
}
