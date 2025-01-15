#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub enabled: bool,
    pub proxy_type: ProxyType,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, Debug)]
pub enum ProxyType {
    Socks4,
    Socks5,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            enabled: false,
            proxy_type: ProxyType::Socks5,
            host: String::new(),
            port: 1080,
            username: None,
            password: None,
        }
    }
}