# IronEye

**IronEye** is a Rust-based Active Directory enumeration and attack toolkit for internal network assessments. It gives penetration testers, red teamers, and security researchers a single interactive console for LDAP reconnaissance, Kerberos protocol attacks, credential operations, and Active Directory object manipulation.

> ⚠️ **Authorized use only.** IronEye is built for sanctioned penetration testing, red-team engagements, and security research. Only use it against systems you own or are explicitly authorized to test.

<img width="1071" height="536" alt="image" src="https://github.com/user-attachments/assets/db3d3e30-6f04-4fec-bd17-67af39b065ba" />


---

## Table of Contents

- [Features](#features)
- [Install & Build](#install--build)
- [Quick Start](#quick-start)
- [Modules](#modules)
  - [Connect — LDAP Reconnaissance](#connect--ldap-reconnaissance)
  - [Deep Queries](#deep-queries)
  - [Actions — AD Object Manipulation](#actions--ad-object-manipulation)
  - [Cerberos — Kerberos Attacks](#cerberos--kerberos-attacks)
  - [User Enumeration & Password Spray](#user-enumeration--password-spray)
  - [Supporting Tools](#supporting-tools)
- [OPSEC Settings](#opsec-settings)
- [Keyboard Controls](#keyboard-controls)
- [Disclaimer](#disclaimer)

---

## Features

- **Flexible authentication** — password, Kerberos (ccache / PtT), and Pass-the-Certificate (Schannel).
- **LDAP reconnaissance** — SID/GUID lookups, domain controllers, SPNs, ACL/DACL inspection, machine account quota, password policy, and arbitrary custom LDAP queries.
- **Deep queries** — bulk enumeration of users, computers, groups, trusts, GPOs, OUs, subnets, delegations, PKI (ADCS), SCCM, SCOM, and DNS, plus hunts for fileshares, SQL servers, and WSUS.
- **Active Directory actions** — create/delete users and computers, group membership changes, UAC flags, password resets, RBCD, DACL ACEs, ownership changes, and ADIDNS management.
- **Shadow Credentials** — list, add, remove, and clear `msDS-KeyCredentialLink` entries.
- **Kerberos attacks (Cerberos module)** — request TGT/TGS, S4U2Self / S4U2Proxy, AS-REP roasting, Kerberoasting, ticket renewal, ticket crafting (Golden/Silver), and ccache/kirbi conversion.
- **Credential attacks** — LDAP password spraying and LDAP-ping user enumeration.
- **OPSEC controls** — tunable encryption types, clock skew, address flags, DNS lookups, ticket lifetimes, and a background keep-alive.
- **Quality of life** — persistent command history, tab completion, a KRB5 config generator, and graceful Ctrl-C handling (cancel the current action instead of killing the app).

---

## Install & Build

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

### Build

```bash
cargo build --release
```

The compiled binary is written to `target/release/ironeye`.

---

## Quick Start

Launch the interactive console:

```bash
./target/release/ironeye
```

Choose a module from the main menu and follow the prompts. A typical first run connects to a domain over LDAP:

```
-u tywin.lannister -p powerkingftw135 -d SEVENKINGDOMS.LOCAL -i 10.2.10.10
```

<img width="824" height="265" alt="image" src="https://github.com/user-attachments/assets/235fe1a6-2510-49b3-b34f-9e7a5c8b4d97" />


---

## Modules

### Connect — LDAP Reconnaissance

The **Connect** module authenticates to a domain controller and drops you into a command menu scoped to that session. Supported authentication modes:

- **Password:** `-u <user> -p <pass> -d <domain> -i <dc_ip>`
- **Kerberos (PtT):** export a ticket to `KRB5CCNAME`, then connect with the Kerberos option.
- **Pass-the-Certificate:** authenticate with a PFX/PEM client certificate over LDAPS/StartTLS.

From the session menu you can run SID/GUID lookups, enumerate domain controllers and SPNs, inspect ACLs/DACLs, check the machine account quota and password policy, run `net`-style queries, issue custom LDAP queries, and open the Deep Queries and Actions sub-menus.

<img width="468" height="413" alt="image" src="https://github.com/user-attachments/assets/2f046b5b-94f9-4e3c-bdbb-56a2bf3b9143" />


### Deep Queries

Bulk enumeration across the directory: users, computers, groups, trusts, subnets, GPOs, OUs, delegations, service connection points, and PKI/SCCM/SCOM infrastructure — plus a DNS dump and targeted hunts for fileshares, SQL servers, and WSUS servers.

<img width="388" height="546" alt="image" src="https://github.com/user-attachments/assets/97f2a17f-5211-41f1-ad87-e3fd1e19fb9a" />


### Actions — AD Object Manipulation

Write operations against the directory (subject to your privileges): add/delete computers and users, manage SPNs and group membership, enable/disable accounts, reset passwords, edit UAC flags, configure RBCD, add/remove DACL ACEs, change object ownership, manage ADIDNS records, and perform Shadow Credentials operations.

<img width="469" height="638" alt="image" src="https://github.com/user-attachments/assets/e735401b-97c4-4d2c-abd3-2c2f28683b7c" />


### Cerberos — Kerberos Attacks

A dedicated Kerberos module (a library conversion of [cerbero](https://github.com/zer1t0/cerbero)). Enter commands at the prompt:

| Command | Description |
| --- | --- |
| `ask-tgt` | Request a TGT (password or `--hash`) |
| `ask-tgs` | Request a service ticket |
| `ask-s4u2self` / `ask-s4u2proxy` | Constrained delegation abuse |
| `asreproast` | AS-REP roast users without pre-auth |
| `kerberoast` | Request and extract crackable service-ticket hashes |
| `renew` | Renew an existing ticket — no credentials needed (`--monitor` auto-renews until renew-till) |
| `craft` | Forge Golden / Silver tickets |
| `convert` | Convert between ccache and kirbi formats |
| `export` / `list` / `hash` | Set `KRB5CCNAME`, list a ccache, compute Kerberos hashes |

Example — renew a ticket you captured but have no credentials for, and keep it alive over a long engagement:

```
renew -t ticket.ccache -i 192.168.1.10 --monitor
```
<img width="1596" height="681" alt="image" src="https://github.com/user-attachments/assets/3b6790be-d8a5-45d9-bc3d-08fc60de51c2" />


### User Enumeration & Password Spray

- **User Enumeration** uses the LDAP-ping method to validate usernames without authenticating.
- **Password Spray** tests one or more passwords across a user list over LDAP, with OPSEC-aware pacing.

<img width="1249" height="253" alt="image" src="https://github.com/user-attachments/assets/b5beeddc-5fb1-4f91-8d83-8be49410af91" />


<img width="1211" height="394" alt="image" src="https://github.com/user-attachments/assets/bacfc759-b85a-4564-a17b-e119d3aa473c" />


### Supporting Tools

- **Generate KRB5 Conf** — build a working `krb5.conf` for a target realm.
- **History Management** — view, search, and clear per-module command history.
- **Debug Settings** — adjust verbosity (including Kerberos library logging).

---

## OPSEC Settings

The **OPSEC Settings** menu controls how noisy IronEye is on the wire: encryption-type policy, clock skew, address flags in Kerberos requests, DNS lookups for KDC/realm discovery, ticket lifetimes, and a background LDAP keep-alive that prevents idle-connection drops (and the extra authentication events a reconnect would generate).

<img width="607" height="590" alt="image" src="https://github.com/user-attachments/assets/cef1a9df-165f-4755-94f6-30ed02f9bef8" />


---

## Keyboard Controls

- **Arrow keys / Enter** — navigate and select menu items.
- **Tab** — path and command completion where available.
- **Ctrl-C** — cancels the current action (or a long-running mode such as `renew --monitor`) and returns to the menu. At the main menu it prompts for a deliberate exit. IronEye is only terminated through the **Exit** option.

---

## Disclaimer

IronEye is intended for legal, authorized security testing and education only. The authors and contributors accept no liability for misuse or for any damage caused by this tool. You are responsible for complying with all applicable laws and for obtaining proper authorization before testing any system.

## Credits
[https://gitlab.com/Zer1i0/cerbero](https://github.com/zer1t0/cerbero)

https://github.com/g0h4n/PassTheCert-rs

