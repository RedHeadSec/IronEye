# IronEye

IronEye is a Rust-based Active Directory enumeration and security assessment tool designed for use in internal network environments. It enables penetration testers, red teamers, and security researchers to interact with LDAP, Kerberos, and SMB services efficiently.

The tool supports both password and Kerberos authentication, allowing for credentialed LDAP queries, password spraying, TGT requests, and more.

Key Features
1. LDAP Enumeration
Perform LDAP reconnaissance without authentication (LDAP Ping).
Retrieve users, computers, groups, and organizational units (OUs).
Query password policies, machine quotas, and domain trusts.
Custom LDAP queries for advanced searches.
Supports Kerberos authentication via GSSAPI.
2. Kerberos Support
Request a Ticket Granting Ticket (TGT) using credentials.
Supports Kerberos password authentication and NTLM hashes.
Uses the KRB5CCNAME environment variable for tickets.
Can export and use ccache files (*.ccache).
3. Password Spraying
Perform efficient and controlled password spraying against LDAP.
Detect locked or disabled accounts to avoid lockout issues.
Supports proxying through SOCKS4 and SOCKS5.
Handles jitter, delays, and thread control.
4. Proxy Support
Proxy all network connections via SOCKS4/SOCKS5.
Ensures anonymity when interacting with LDAP, Kerberos, and SMB.
Built-in helper functions to validate and parse proxy URLs.
5. Cerbero Integration (For Kerberos Operations)
Leverages Cerbero for AS-REP roasting, Kerberoasting, and password bruteforcing.
Automates TGT requests, Kerberos ticket handling, and ticket export.
Works across Linux, Windows, and macOS with architecture-specific binaries.
Installation
Linux/macOS
Ensure you have Rust installed:

bash
Copy
Edit
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
Clone and build IronEye:

bash
Copy
Edit
git clone https://github.com/your-repo/ironeye.git
cd ironeye
cargo build --release
Windows
Install Rust with MSVC toolchain:
Download from Rustup.
Clone and build:
powershell
Copy
Edit
git clone https://github.com/your-repo/ironeye.git
cd ironeye
cargo build --release
Install MIT Kerberos for Windows if using Kerberos authentication.
Usage
Run the tool:

bash
Copy
Edit
./ironeye
Select the appropriate module from the interactive menu.

1. LDAP Connect
Connect to an LDAP server and query domain information.

bash
Copy
Edit
-u <username> -p <password> -d <domain> -i <dc-ip> [-s] [-t] [-k] [--proxy socks5://127.0.0.1:1080]
-s → Use LDAPS instead of LDAP.
-t → Enable timestamp logging.
-k → Use Kerberos authentication (KRB5CCNAME must be set).
