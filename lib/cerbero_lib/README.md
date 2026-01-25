# Cerbero Library

Library version of [cerbero](https://gitlab.com/Zer1t0/cerbero) for integration with IronEye.

## Structure

This library lives within the IronEye project at `lib/cerbero_lib/`.

## Setup

Copy source files from the original cerbero:

```bash
cd lib/cerbero_lib
chmod +x complete_conversion.sh
./complete_conversion.sh
```

This copies all source modules from `../../../cerbero/src/` to `src/`.

## Usage in IronEye

In `ironeye/Cargo.toml`:

```toml
[dependencies]
cerbero_lib = { path = "lib/cerbero_lib", default-features = false }
```

Then use in code:

```rust
use cerbero_lib::{KrbUser, request_tgt, KdcComm, TransportProtocol};

fn attack() -> cerbero_lib::Result<()> {
    let user = KrbUser::new("username", "domain.local");
    // ... use cerbero_lib functions
    Ok(())
}
```

## Features

- **Default**: Library only (no CLI dependencies)
- **`cli`**: Enables standalone binary

Build standalone binary:
```bash
cargo build --features cli
```

## Public API

Main exports:
- `KrbUser`, `Vault`, `FileVault` - Core types
- `request_tgt()`, `request_tgs()` - Ticket operations  
- `KdcComm`, `new_krb_channel()` - Network communication
- `as_rep_to_crack_string()`, `tgs_to_crack_string()` - Attack functions
- `craft_ticket_info()` - Golden/silver tickets

## Credits

Original cerbero by Eloy (zer1t0ps@protonmail.com)
- https://gitlab.com/Zer1t0/cerbero

Based on Impacket, Rubeus, and Mimikatz.

## License

AGPL-3.0 (same as original cerbero)
