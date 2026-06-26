# IronEye

IronEye is a Rust-based Active Directory enumeration and security assessment tool designed for use in internal network environments. It enables penetration testers, red teamers, and security researchers to interact with LDAP, Kerberos, and SMB services efficiently.

The tool supports password and Kerberos authentication, allowing for credentialed LDAP queries, Kerberos protocol attacks, password spraying, Shadow Credentials abuse, ACL manipulation, DNS management, and more.

## Install and Compile

### Prerequisites

**Linux (Debian/Ubuntu/Kali):**
```bash
sudo apt install pkg-config libssl-dev libkrb5-dev libclang-dev
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install pkg-config openssl-devel krb5-devel clang-devel
```

**macOS:**
```bash
brew install openssl pkg-config
```

**Windows:** No additional dependencies required — OpenSSL is vendored automatically.

### Build

```bash
cargo build --release
```

## Table of Contents

- [Authentication / Connect](#authentication--connect)
- [Connect Sub-Modules](#connect-sub-modules)
- [Deep Queries](#deep-queries)
- [Actions Menu](#actions-menu)
- [Shadow Credentials](#shadow-credentials)
- [DNS Management (ADIDNS)](#dns-management-adidns)
- [ACL / DACL Management](#acl--dacl-management)
- [Cerberos Module (Kerberos Attacks)](#cerberos-module-kerberos-attacks)
- [Password Spray](#password-spray)
- [User Enumeration](#user-enumeration)
- [History Management](#history-management)
- [Debug Settings](#debug-settings)
- [Development Status](#development-status)

---

## Authentication / Connect

IronEye supports three authentication modes for LDAP connections.

**Password authentication:**
```
-u tywin.lannister -p powerkingftw135 -d SEVENKINGDOMS.LOCAL -i 10.2.10.10
```

**Kerberos authentication (FQDN):**

Requires krb5.conf configuration. A sample is provided. Use the `Generate KRB5 Conf` option from the main menu to create one interactively.
```
-u robb.stark -d NORTH.SEVENKINGDOMS.LOCAL -i WINTERFELL.NORTH.SEVENKINGDOMS.LOCAL -k -s
```

**Kerberos authentication (IP with DC hostname):**
```
-u robb.stark -d NORTH.SEVENKINGDOMS.LOCAL -i 10.2.10.10 -k -dc-host WINTERFELL.NORTH.SEVENKINGDOMS.LOCAL
```

**Connection arguments:**
```
-u <user> -p <password> -d <domain> -i <FQDN/IP> [-s (LDAPS)] [-t (timestamps)] [-k (Kerberos)] [-dc-host <hostname>]
```

<!-- SCREENSHOT: Main menu after launch -->
<!-- SCREENSHOT: Successful LDAP connection -->

---

## Connect Sub-Modules

After authenticating, the Connect module provides the following enumeration and query commands:

| Command | Description |
|---------|-------------|
| Get SID/GUID | Query an object's Security Identifier or GUID |
| From SID/GUID | Reverse lookup — resolve an object from its SID or GUID |
| Get Domain Controllers | Enumerate all domain controllers in the domain |
| Get SPNs | Enumerate Service Principal Names for Kerberoasting |
| Get ACE/DACL | Analyze access control entries and DACLs on objects |
| Machine Quota | Query the Machine Account Quota (ms-DS-MachineAccountQuota) |
| Net Commands | LDAP-based net commands (user, group, computer info) |
| Password Policy | Retrieve the domain password and lockout policy |
| Deep-Queries | Complex enumeration queries (see below) |
| Custom LDAP Query | Execute raw LDAP queries with custom filters and attributes |
| Whoami | Display current authenticated session info |
| Actions | Write/modification operations (see below) |

<!-- SCREENSHOT: Connect sub-modules menu -->

---

## Deep Queries

Predefined complex LDAP queries for comprehensive AD enumeration:

| Query | Description |
|-------|-------------|
| Domain Trusts | Enumerate trust relationships between domains |
| All Users | List all domain user accounts with attributes |
| All Computers | Enumerate all computer objects |
| All Groups | List all security and distribution groups |
| All Subnets | Enumerate Active Directory site subnets |
| All GPOs | List all Group Policy Objects |
| All PKI Information | Certificate Services / ADCS discovery |
| All SCCM Information | System Center Configuration Manager enumeration |
| All SCOM Information | System Center Operations Manager discovery |
| All Organization Units | OU structure enumeration |
| All Delegations | Kerberos delegation enumeration (unconstrained, constrained, RBCD) |
| All Service Connection Points | SCP enumeration |
| DNS Dump | Full DNS zone record dump |

<!-- SCREENSHOT: Deep queries menu -->
<!-- SCREENSHOT: Example deep query output (e.g. delegations or trusts) -->

---

## Actions Menu

The Actions menu provides write/modification operations against AD objects. These require appropriate permissions on the target.

### Account Management

| Action | Description |
|--------|-------------|
| Add Computer | Create a new computer object with optional random password |
| Add User | Create a new user account with optional random password |
| Delete Computer | Remove a computer object from AD |
| Delete Object | Delete any AD object (requires typing DELETE to confirm) |
| Enable Account | Re-enable a disabled user or computer account |
| Disable Account | Disable a user or computer account |

### Credential and Access

| Action | Description |
|--------|-------------|
| Set Password | Reset a user's password (admin reset or old-password change) |
| Set UAC Flags | Modify User Account Control flags (DONT_EXPIRE_PASSWORD, DONT_REQUIRE_PREAUTH, TRUSTED_FOR_DELEGATION, etc.) |

### Group and Membership

| Action | Description |
|--------|-------------|
| Add User to Group | Add a user to a security group |
| Remove User from Group | Remove a user from group membership |

### Delegation

| Action | Description |
|--------|-------------|
| Set RBCD | Configure Resource-Based Constrained Delegation on a target computer |
| Remove RBCD | Remove RBCD delegation permissions |

### ACL / Ownership

| Action | Description |
|--------|-------------|
| Add DACL ACE | Grant permissions (GenericAll, DCSync, WriteDACL, WriteOwner) |
| Remove DACL ACE | Revoke specific DACL permissions |
| Set Owner | Change the owner of an AD object |

### SPN, DNS, Shadow Credentials

| Action | Description |
|--------|-------------|
| SPN Management | List, add, or delete Service Principal Names on objects |
| DNS Management | AD-Integrated DNS record manipulation (see below) |
| Shadow Credentials | msDS-KeyCredentialLink abuse (see below) |

### Connection

| Action | Description |
|--------|-------------|
| Reconnect with Secure Connection | Upgrade current session to LDAPS or STARTTLS |

<!-- SCREENSHOT: Actions menu -->

---

## Shadow Credentials

The Shadow Credentials module manipulates the `msDS-KeyCredentialLink` attribute to enable PKINIT authentication without a CA-issued certificate. Requires write access to the target's `msDS-KeyCredentialLink` attribute.

| Operation | Description |
|-----------|-------------|
| List Key Credentials | Display existing shadow credentials (DeviceId, creation time, key usage, key source, KeyID) |
| Add Shadow Credential | Generate an RSA 2048 key pair, write the key credential to AD, and export a PFX certificate for PKINIT |
| Remove Shadow Credential | Remove a specific credential by DeviceId |
| Clear All Key Credentials | Wipe all key credentials from the target (requires CLEAR confirmation) |

**Adding a shadow credential:**
```
Target: darth.vader
Output PFX: shadow_creds.pfx
PFX Password: ironeye
```

The generated PFX can be used with tools like Certipy for PKINIT authentication:
```bash
certipy auth -pfx shadow_creds.pfx -password ironeye -domain galactic.empire -dc-ip 10.1.10.10
```

<!-- SCREENSHOT: Shadow Credentials submenu -->
<!-- SCREENSHOT: Adding a shadow credential and PFX output -->

---

## DNS Management (ADIDNS)

AD-Integrated DNS management for record manipulation. Searches both `DomainDnsZones` and `ForestDnsZones` partitions.

| Operation | Description |
|-----------|-------------|
| Query DNS Zones | Enumerate all DNS zones in the domain |
| Query DNS Record | Search for specific A/AAAA/CNAME records by name |
| Add A Record | Create a new DNS A record |
| Modify A Record | Update an existing A record's IP address |
| Remove (Tombstone) Record | Soft-delete a DNS record (tombstone) |
| Delete Record (LDAP) | Hard-delete a DNS record via LDAP |

<!-- SCREENSHOT: DNS management menu -->
<!-- SCREENSHOT: DNS zone query output -->

---

## ACL / DACL Management

Add or remove discretionary access control entries on AD objects. Available rights:

| Right | Description |
|-------|-------------|
| GenericAll | Full control over the target object |
| DCSync | Grant DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, and DS-Replication-Get-Changes-In-Filtered-Set on the domain object |
| WriteDACL | Permission to modify the object's DACL |
| WriteOwner | Permission to change the object's owner |

Both add and remove operations are supported from the Actions menu.

<!-- SCREENSHOT: DACL ACE add/remove example -->

---

## Cerberos Module (Kerberos Attacks)

Built-in Kerberos protocol attack capabilities via the integrated cerbero library.

### Ticket Operations

| Command | Description |
|---------|-------------|
| ask-tgt | Request a Ticket Granting Ticket (TGT) using password or NTLM hash |
| ask-tgs | Request a Ticket Granting Service ticket for a target SPN |
| ask-s4u2self | S4U2Self — impersonate a user to yourself |
| ask-s4u2proxy | S4U2Proxy — forward impersonation to another service |

### Roasting Attacks

| Command | Description |
|---------|-------------|
| asreproast | AS-REP roast users with DONT_REQUIRE_PREAUTH set. Supports single user or file input. Output in Hashcat or John format. |
| kerberoast | Kerberoast SPN accounts. Input as user:spn pairs (single or file). |

### Ticket Manipulation

| Command | Description |
|---------|-------------|
| convert | Convert between ccache and .krb ticket formats |
| craft | Forge golden/silver tickets with full parameter control (SID, RID, groups, key type, SPN) |

### Utility

| Command | Description |
|---------|-------------|
| hash | Calculate Kerberos keys (RC4, AES128, AES256) from a password |
| list | Display tickets stored in a ccache file |
| export | Set the KRB5CCNAME environment variable to a ccache file path |

<!-- SCREENSHOT: Cerberos module menu -->
<!-- SCREENSHOT: ASREPRoast or Kerberoast output -->

---

## Password Spray

LDAP-based password spraying with lockout protection and multi-DC support.

**Arguments:**
```
--users <user_or_file> --passwords <pass_or_file> --domain <domain> --dc-ip <ip>[,<ip2>]
  [--threads <num>]               Thread count (default: 10)
  [--delay <seconds>]             Delay between spray rounds
  [--jitter <ms>]                 Random jitter between attempts
  [--continue-on-success]         Don't stop on first valid credential
  [--lockout-threshold <num>]     Stop after N failed attempts per account
  [--lockout-window <seconds>]    Lockout observation window
  [--verbose]                     Verbosity (0=successes only, 1=all attempts, 2=full debug)
  [--timestamp]                   Prefix output with timestamps
```

**Example:**
```
--users users.txt --passwords passwords.txt --domain corp.local --dc-ip 192.168.1.10 --jitter 10 --delay 10 --continue-on-success --verbose --timestamp --lockout-threshold 5 --lockout-window 600
```

<!-- SCREENSHOT: Password spray execution and results -->

---

## User Enumeration

LDAP ping-based username enumeration without full authentication.

**Arguments:**
```
--userfile <path> --domain <domain> --dc-ip <ip> --output <filename> [--timestamp] [--threads <num>]
```

**Example:**
```
--userfile users.txt --domain corp.local --dc-ip 192.168.1.10 --output valid_users.txt --timestamp
```

<!-- SCREENSHOT: User enumeration output -->

---

## History Management

IronEye tracks command usage across sessions in a local SQLite database.

| Option | Description |
|--------|-------------|
| View Recent Commands | Display recent commands across all modules |
| Search History | Pattern search through command history |
| View Statistics | Per-module command frequency and percentages |
| Clear Module History | Delete history for a specific module |
| Cleanup Old Entries | Remove entries older than 30 days |
| Export History to File | Save command history to a text file |
| Clear All History | Full database wipe (double confirmation required) |

Tracked modules: connect, cerbero, spray, userenum, ldapquery, adidns, actions

---

## Debug Settings

Configurable verbosity levels affecting both IronEye and the cerbero library:

| Level | Description |
|-------|-------------|
| 0 | Production mode (disabled) |
| 1 | Basic — connections, command execution |
| 2 | Verbose — LDAP queries, authentication attempts |
| 3 | Full trace — raw responses, thread details |

---

## Development Status

| Feature | Description | Status |
|---------|-------------|--------|
| Kerberos Auth | Kerberos-based LDAP authentication via GSSAPI | Done |
| Multi-Platform | Tested on Linux, macOS, Windows | Done |
| Password Spray | Multi-threaded LDAP spray with lockout protection | Done |
| Shadow Credentials | msDS-KeyCredentialLink abuse with PFX export | Done |
| ADIDNS Management | AD-Integrated DNS record manipulation | Done |
| ACL/DACL Modification | GenericAll, DCSync, WriteDACL, WriteOwner ACE management | Done |
| RBCD | Resource-Based Constrained Delegation set/remove | Done |
| Kerberos Attacks | ASREPRoast, Kerberoast, S4U2Self, S4U2Proxy, ticket forging | Done |
| Deep Queries | Trusts, PKI, SCCM, SCOM, GPO, delegations, SCP enumeration | Done |
| History Tracking | SQLite-backed command history with search and export | Done |
| Proxy Support | Native SOCKS support (works with proxychains4 in the meantime) | TBD |
