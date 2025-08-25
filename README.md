# IronEye

IronEye is a Rust-based Active Directory enumeration and security assessment tool designed for use in internal network environments. It enables penetration testers, red teamers, and security researchers to interact with LDAP, Kerberos, and SMB services efficiently.
The tool supports both password and Kerberos authentication, allowing for credentialed LDAP queries, password spraying, TGT requests, and more. This project was my first ever real tool development project in Rust to force myself to stay interested and learn the language. Most of this is likely not prime l33t coding, the most efficent, or 100% bug free. Feel free to add PRs or give me pointers for improvement or modules. Use at your own risk and I always recommend testing in a lab environment prior to any authorized client work. 

## Install and Compile
```bash
sudo apt install pkg-config libssl-dev
sudo apt install libclang-dev clang
cargo build --release
```

## Connect Module
Authenticate using password
```bash
-u tywin.lannister -p powerkingftw135 -d SEVENKINGDOMS.LOCAL -i 10.2.10.10
```
Authenticate using Kerberos to LDAPS

Note: Youll need to set up the KDC realm usually found at /etc/krb5.conf. A sample is provided.

I'd LOVE to have this all setup within the tool similar to another awesome tool this took inspriation from: https://github.com/Synzack/ldapper which only needs the contents of the KRB5CCNAME file. Gave it several attempts but ran into implementation issues. Maybe someone smarter than I has an example or can PR for it.  
```bash
-u robb.stark -d NORTH.SEVENKINGDOMS.LOCAL -i WINTERFELL.NORTH.SEVENKINGDOMS.LOCAL -k -s
```
Connection Arguments:
```
-u <user> -p <password> -d <domain -i <FQDN/IP> [-s <ldaps>] [-t <timestamp>] [-k <Kerberos Auth>]
```

![image](https://github.com/user-attachments/assets/48844bf1-bcf4-4f62-8209-b33f3c499828)


![alt text](images/image-3.png)


## Connect - Sub Modules
![alt text](images/sub_modules.png)

- **Get SID/GUID** - Get the SID/GUID of a domain object
- **From SID/GUID** - Find the CN/Name of a SID/GUID
- **Get SPNs** - Pull and export all domain SPNs
- **Query Groups** - Pull groups for a user or all user groups
- **Machine Quota** - Get the MAQ for the domain
- **Net Commands** - Net User/Group commands
- **Password Policy** - Pull the domain password poilicies including fine-grained ones
- **Deep-Queries** - Quereies for interesting domain assets or information
- **Custom Ldap** - Run a custom LDAP query (Bofhound Compatible)

<img width="1364" height="753" alt="image" src="https://github.com/user-attachments/assets/c5eae49e-546b-41d6-ab70-88f23a1b586c" /> <br>


**Using https://github.com/coffeegist/bofhound:**
<img width="695" height="855" alt="image" src="https://github.com/user-attachments/assets/beb0f125-6778-41ce-9eba-96a2aada34e2" />


## Cerberos Module
Refer to https://github.com/zer1t0/cerbero for usage details/examples.

Fun Fact: I rewrote the original Cerbero code to be used in a library format for this program just to realize later that same day someone had already done it, but it was to late as I had already implemented it into the main code base. Oh 🐋! 
```bash
Kerberos protocol attacker

USAGE:
    cerbero <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    ask           Ask for tickets
    asreproast    Perform a asreproast attack
    brute         Perform a bruteforce attack against kerberos protocol
    convert       Converts tickets files between ccache and krb
    craft         Create golden and silver tickets
    hash          Calculate password hashes/Kerberos keys
    help          Prints this message or the help of the given subcommand(s)
    kerberoast    Perform a kerberoast attack
    list          Describe the credentials stored in a file
    export        Export file to KRB5CCNAME variable. (export /path/to/file.ccache)
```
![alt text](images/image-2.png)


## User Enumeration / Password Spray Modules
User Enumeration:
```
Argument format: --userfile <path> --domain <domain> --dc-ip <ip> --output <filename> [--timestamp]
Example: --userfile users.txt --domain corp.local --dc-ip 192.168.1.10 --output results.txt --timestamp
```

Password Spray:
```
Argument format: --users <user/path> --passwords <pass/path> --domain <domain> --dc-ip <ip> [--threads <num>] [--jitter <ms>] [--delay <ms>] [--continue-on-success] [--verbose] [--timestamp] [--lockout-threshold <num>] [--lockout-window <seconds>]
Example: --users users.txt --passwords passwords.txt --domain corp.local --dc-ip 192.168.1.10 --jitter 10 --delay 10 --continue-on-success --verbose --timestamp  --lockout-threshold 5 --lockout-window 600
```
![image](https://github.com/user-attachments/assets/17baadbe-a246-417c-96e1-61f37f5dc892)

<img width="1145" height="839" alt="image" src="https://github.com/user-attachments/assets/aa039041-92ac-4267-86a7-b47bb63aeae1" />



## Current / Future Development

| Feature           | Description                                  | Status   |
|------------------|----------------------------------|---------|
| Kerberos Auth   | Supports Kerberos-based authentication | ✅ Working (For Linux) - Does not work currently for MAC due to differences in dependencies - Not tested on Windows|
| Threading Support   | Threading for the password spray has not been implemented yet.       |  ✅ Implemented 08/24/25 |
| Proxy Support   | While native SOCKS support is desired, this tool works well with proxychains4 so currently is on the back burner.       | ❌ TBD  |
| SMB Modules | Currently on the table but not under active implementation at this time   | ❌ TBD |
