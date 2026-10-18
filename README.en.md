# Bifrost

[Francais](README.md) | English

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Musyg/Musyg/308e2616361e5e3b06cf4725e4598ffbcef7d39e/assets/bifrost/bifrost-fond-sombre.png">
  <img src="https://raw.githubusercontent.com/Musyg/Musyg/308e2616361e5e3b06cf4725e4598ffbcef7d39e/assets/bifrost/bifrost-couleur.png" alt="Bifrost - bridge of light" width="360">
</picture>

A self-hosted VPN for Windows 11 and Linux, written in Rust. Three objectives, in this order:

1. **Do not leak.** A fail-closed kill switch enforced by the operating system, with checks for tunnel loss, reconnection, startup and daemon failure.
2. **Do not get blocked.** Transport selection and supervision for networks that filter traffic through DPI or censorship.
3. **Do not let the OS phone home.** Reduce operating-system telemetry at its source and reject telemetry names before traffic enters the tunnel.

The software is called Bifrost. Early design documents used the working name "Hyper VPN" until 21 August 2026; that name remains in Git history.

## Current implementation

Bifrost is in development. The first-objective MVP is implemented. The daemon and CLI are available. The graphical shell (Tauri window and tray, [document 08](docs/08-coquille-graphique.md), in French) is in the repository, outside the MVP; it has its own packages (see Packages). It runs without elevation; on Windows, the daemon's channel admits the members of a local access group that the installer creates empty, and a member's shell has the three commands the daemon opens to members: status, `connect-stored` and `disconnect`.

The connection path now uses transport selection. WireGuard runs directly; VLESS + REALITY and Hysteria2 profiles run through sing-box, with a TUN interface and a SOCKS5 forwarding path. DNS filtering and Windows telemetry settings are implemented. Service-specific WFP telemetry filters remain a separate defense-in-depth layer, with their measured effects recorded individually.

| Component | Linux | Windows |
|---|---|---|
| Kill switch | nftables `inet`, drop policy and fwmark | User-mode WFP through BFE |
| WireGuard | Kernel module controlled through netlink | WireGuardNT, with handshake and data-path tests |
| Third-party transport path | TUN, routing by the core's identity, SOCKS5 forwarding | Wintun, interface-bound transport sockets, SOCKS5 forwarding |
| DNS | systemd-resolved or `/etc/resolv.conf`; optional dnscrypt-proxy | Interface DNS configuration, WFP restrictions; optional dnscrypt-proxy under LocalService |
| Authenticated IPC | Unix socket and `SO_PEERCRED`: root, and the `bifrost` group limited to three commands | Named pipe and an explicit security descriptor: SYSTEM, Administrators and an optional local access group (`--group`) limited to three commands |
| Local comparisons | File integrity, nftables, routing and effective DNS | File integrity, WFP and routing |
| Leak-test harness | Ten vectors, network namespaces and packet captures | `check` runs the DoH-policy check; the other vectors refer to dedicated commands |
| Telemetry controls | DNS filtering | DNS filtering, reversible registry/service/task settings, and separately measured WFP filters |

The current task register is [ETAT.md](ETAT.md). The [French README](README.md) also retains the detailed measurement history and the reasons behind earlier corrections. This English guide covers the current implementation, its use and the scope of its checks.

## What Bifrost is built for

Privacy, control over network traffic and resistance to censorship. A single, unshared exit IP is a stable identifier, so a single-hop self-hosted tunnel is not an anonymity guarantee. Chaining through Tor or Nym belongs to the documented design work, not to the capabilities listed above.

A tunnel also does not make a logged-in account anonymous or remove browser identifiers. See the [threat models and chaining design](docs/05-anonymat-chainage.md) for that distinction.

## Architecture

```text
crates/
  bifrost-core/       domain types and state machine
  bifrost-evasion/    transport-selection policy
  bifrost-firewall/   nftables and WFP kill switch
  bifrost-dns/        system DNS and embedded-resolver configuration
  bifrost-telemetrie/ telemetry catalogues and reversible settings
  bifrost-coffre/     profile protection at rest
  bifrost-amorce/     profile retrieval and signature verification
  bifrost-ipc/        authenticated IPC schema and transport
  bifrost-daemon/     privileged daemon, tunnel and test harness
  bifrost-cli/        unprivileged client and local comparisons
  bifrost-coquille/   graphical shell logic: state, commands, view
  bifrost-icone/      Bifrost icon drawn by code (PNG and ICO, no dependency)
gui/                  graphical shell window and tray (Tauri 2), separate workspace
```

Two principles shape the implementation.

**Firewall policy is data.** Pure functions generate the nftables ruleset and the WFP filter plan. Unit tests can inspect those plans without privileges, network interfaces or the target operating system. The system-facing code applies them.

**The state machine does not perform system operations.** It turns a state and an event into actions for the daemon. Tests check that a connection or retry cannot disarm the kill switch. An explicit `disconnect` removes it last, after the tunnel has been dismantled.

Third-party transport cores run as separate processes, not as libraries linked into the daemon. The core's identity is also the identity allowed to carry traffic outside the tunnel. The embedded DNS resolver has a different account and a different exception; these roles are not interchangeable.

HTTP retrieval and TLS inspection belong to the unprivileged client. They do not add an HTTP/TLS parser to the long-running privileged daemon.

## Build

```bash
cargo build --workspace --locked
```

The workspace declares Rust 1.93 or later and edition 2024. [rust-toolchain.toml](rust-toolchain.toml) pins the build toolchain to 1.98.0, with rustfmt and Clippy. On Linux, the `wireguard` kernel module and `nft` executable are needed at runtime.

On Windows/MSVC, [.cargo/config.toml](.cargo/config.toml) enables Control Flow Guard and, for x86_64, CET compatibility marking. On Linux, the binary checks cover PIE, full RELRO and a non-executable stack.

Build from inside the repository. Running Cargo elsewhere with `--manifest-path` does not load this local configuration. `RUSTFLAGS` or `CARGO_ENCODED_RUSTFLAGS`, even when empty, replace rather than extend the configured flags. To add Windows flags without losing the configured hardening, use `CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS`, or repeat both hardening flags explicitly.

The `durcissement_binaire` tests inspect executable headers. CI also builds the shipped binaries in release mode and reads their headers:

```bash
cargo build --release --locked
BIFROST_REPERTOIRE_LIVRE=target/release cargo test --locked --workspace --test durcissement_binaire -- --ignored
```

## Use

Start from [examples/tunnel.toml](examples/tunnel.toml). A profile contains authentication secrets. On Linux, a plaintext profile must not be readable by its group or by other users:

```bash
chmod 600 /etc/bifrost/tunnel.toml
bifrost-daemon --genkey
```

After starting the daemon as root or through the installed service, use the client:

```bash
bifrost-cli connect
bifrost-cli status
bifrost-cli check
bifrost-cli disconnect
```

Without `--config`, `connect` asks the daemon to open the profile from its own command line (`--profil`, default `/etc/bifrost/tunnel.toml` on Linux). It sends no caller-selected file path. A member of the `bifrost` group can therefore connect without gaining the right to read the private key. `connect --config` instead sends a profile the client has read itself.

`--json` provides script-readable output. Command names, configuration fields and identifiers remain in French where that is the CLI's actual syntax; examples below use the executable name `bifrost-cli`.

Before sending anything, the client checks the IPC server's identity: root peer credentials on Linux, or a pipe owned by LocalSystem or Administrators on Windows. A rejected identity sends no profile and exits with code 4. The proof commands use the stricter documented identity rules described below.

A busy Windows pipe is allowed up to two seconds to become available. A connected client has ten seconds to deliver a complete request; this is a request-reading deadline, not a command-execution deadline. Connection-level acceptance failures do not stop the entire IPC service. A failure of the listener itself stops the daemon in an orderly way, leaving the kill switch in its current state.

If the daemon dies while the kill switch is armed, traffic stays blocked. To remove the filters explicitly:

```bash
bifrost-daemon --cleanup-firewall
```

The CLI also has an explicit local recovery command when the daemon is dead or unresponsive:

```bash
bifrost-cli emergency-disarm --je-sais-ce-que-je-fais
```

It bypasses the daemon and opens cleartext traffic. It is an emergency operation, not a substitute for `disconnect`; a still-running daemon could otherwise believe its protection remains armed. The command requires the corresponding system privileges and the explicit acknowledgement flag. Before disarming, it reports what holds the daemon channel, without writing to it: the daemon itself, another process, a server that accepts no further connection (possibly a frozen daemon), or a channel this account cannot open. It warns; it never refuses.

### Network warning

Arming the kill switch cuts outgoing traffic outside the tunnel, including already established SSH or RDP sessions. There is no general exception for established connections. Run blocking tests in an isolated network namespace or on a dedicated machine that you do not depend on remotely.

## Packages

The daemon and CLI have packages: a `.deb` and an `.rpm` for Linux (amd64) and an MSI for Windows (x64). They are **not signed**, no repository serves them and no release carries them: they are CI run artifacts, kept for 7 days (Actions > ci > the run > Artifacts). The `.deb` and `.rpm` (artifact `paquets-linux`) come from every push to `main`, every pull request and a manual run without the `windows` box; the MSI (artifact `paquets-windows`, with its SHA-256 digest) only from a manual run with the `windows` box checked. No version is promised: a package carries the `Cargo.toml` version of the revision that built it. Built on Ubuntu 24.04, the Linux packages target distributions of that generation: the daemon `.deb` requires `libc6 (>= 2.39)`, which neither Debian 12 nor Ubuntu 22.04 provides.

A package installs what the scripts in the next two sections install, at the same paths with the same rights: the same accounts, the same unit (under `/usr/lib/systemd/system`, where packages put it, instead of `/etc/systemd/system`), the same Windows service command line, the `Bifrost` access group included. Like the scripts, it **does not start** the service: on Linux the unit is neither enabled nor started; on Windows the service is registered for automatic startup, as by `install-windows.ps1`, and starts at the next reboot. Like `install-linux.sh`, the Linux packages refuse a service account in the `bifrost` group, and a core and resolver that would share a UID. The `.rpm` creates the accounts and refuses before installing any file (`%pre`): rpm does not install a package whose `%pre` fails, so a refusal installs no file: the machine stays without the package, or with the previous version on an upgrade, and accounts already created remain. The `.deb` refuses at configuration time, its files already in place. `dnscrypt-proxy` and `wireguard.dll` are in no package: the MSI has the service command line name the resolver if it finds `dnscrypt-proxy.exe` already placed in `%ProgramFiles%\Bifrost`, and `wireguard.dll` is placed by hand next to the daemon.

```bash
sudo apt install ./bifrost_<version>_amd64.deb
sudo systemctl enable --now bifrost-daemon   # an explicit decision, as after the script
```

```powershell
msiexec /i bifrost-<version>-x64.msi
```

Removing a package stops the service, removes the kill switch filters (`--cleanup-firewall`), then the service and the binaries; an upgrade does not remove the filters. On Windows, upgrading the MSI from one version to the next is measured (on 2026-10-18, disposable Windows Server 2025 virtual machine, silent install): the old version is removed inside the new version's transaction, without `--cleanup-firewall` or `--uninstall-service`; the service is updated in place and keeps the startup type chosen by the administrator, its command line and the access group (same SID, same members) stay, as does the data under `%ProgramData%\Bifrost`; a running service is restarted on the new binary by Windows Installer and a stopped service is not started; a second MSI of the same version is an upgrade, not a second installation; a failure during the upgrade restores the old version; installing the old version over the new one is refused. As with the scripts, the accounts and the access group stay (the uninstall sections below say how to remove them), and so does any data under `/var/lib/bifrost` or `%ProgramData%\Bifrost`. Purging the `.deb` removes `/var/lib/bifrost` if it is empty and keeps it otherwise, saying so.

The graphical shell has its own packages, `bifrost-gui`: a `.deb` and an `.rpm` (artifact `paquets-gui-linux`, from the same runs as `paquets-linux`) and an MSI, `Bifrost GUI` (artifact `paquets-gui-windows`, with its SHA-256 digest, only from a manual run with the `windows` box checked). They are **not signed** either, and are kept for 7 days as well. They install the `bifrost-gui` binary, a menu entry, its icons and, on Linux, a manual page: no session autostart entry, no maintainer script, no MSI custom action. The `.deb` depends on the tray library the shell loads at run time (`libayatana-appindicator3-1`) and recommends the `bifrost` package without requiring it; the MSI installs into `%ProgramFiles%\Bifrost`, like the daemon's but under a different upgrade code, so removing one leaves the other in place, and it refuses to install without the WebView2 Runtime; like the daemon's, a second MSI of the same version is an upgrade, not a second installation, and a failure during the upgrade restores the old version (measured on 2026-10-18, disposable Windows Server 2025 virtual machine, silent install). Started as root or as an administrator, the shell refuses to start; it commands the daemon from an account in the `bifrost` group on Linux (`sudo usermod -aG bifrost <account>`, then a new session), in the `Bifrost` access group on Windows.

```bash
sudo apt install ./bifrost-gui_<version>_amd64.deb
```

```powershell
msiexec /i bifrost-gui-<version>-x64.msi
```

## Install on systemd

```bash
sudo ./packaging/install-linux.sh
sudo RESOLVEUR=/path/to/dnscrypt-proxy ./packaging/install-linux.sh
```

The installer creates the accounts, installs the binaries and unit, then stops. **It neither enables nor starts the service.** Starting it is an explicit operational decision.

- The `bifrost` group opens the daemon's channel to its members, who have three commands there: status, `connect-stored` (the profile the daemon holds) and `disconnect`. Every other command (`connect --config`, `check`, resume after sleep, the declarations, the TLS inspection verdict) is reserved to root and receives a refusal that names it. An administrator manages its membership.
- `bifrost-coeur` runs third-party transport cores. It has no login shell or home directory and does not belong to the control group.
- `bifrost-resolveur` runs the encrypted DNS resolver. Unlike the core, it has no general cleartext network exemption. Its identity restricts who may use port 53.

The installer refuses to give the core and resolver the same UID. Their declarations live in [packaging/sysusers.d/bifrost.conf](packaging/sysusers.d/bifrost.conf); a `useradd` fallback preserves the same properties when systemd-sysusers is absent.

dnscrypt-proxy is a third-party executable, obtained and verified separately. `RESOLVEUR=` installs it as `/usr/lib/bifrost/dnscrypt-proxy`, owned by root and not writable by the resolver account. Without it, installation can complete, but a profile requesting an embedded resolver fails with an explanation instead of silently falling back to plaintext DNS.

### Uninstall on Linux

Remove the firewall filters before removing the executable that can clean them up:

```bash
sudo systemctl disable --now bifrost-daemon
sudo bifrost-daemon --cleanup-firewall
sudo rm -f /etc/systemd/system/bifrost-daemon.service /usr/lib/sysusers.d/bifrost.conf
sudo rm -f /usr/bin/bifrost-daemon /usr/bin/bifrost-cli
sudo rm -rf /usr/lib/bifrost
sudo systemctl daemon-reload
```

The service accounts are deliberately kept. Remove them separately only after checking that no remaining files belong to their UIDs; reusing an old UID can transfer ownership of those files to another account.

## Install on Windows

From an elevated PowerShell session:

```powershell
.\packaging\install-windows.ps1
.\packaging\install-windows.ps1 -Pilote C:\downloads\wireguard.dll -Resolveur C:\downloads\dnscrypt-proxy.exe
```

The installer places the binaries, hardens the data directory and registers the service. It does not start it. **The Windows service is registered for automatic startup**, however, and starts at the next reboot. This differs from the Linux installer, which does not enable its unit.

The installer also creates the local group `Bifrost`, empty, if it does not exist, and records it in the service command line (`--group`, by SID). This is the channel's **access group**. Its members open the daemon's pipe without elevation and have three commands there, through the CLI or the graphical shell: status, `connect-stored` (the profile the daemon holds, recorded by an administrator) and `disconnect`. Every other command stays with SYSTEM and with tokens whose Administrators group is active (an elevated console): the daemon identifies the caller of each request from the token the pipe presents, and a caller it cannot identify gets the three commands only. On Linux, a member of the `bifrost` group has the same three commands; root, admitted by its uid, keeps the whole channel. Members cannot create a pipe instance, so they cannot hold the channel in the daemon's place, and the client still requires a pipe owned by LocalSystem or Administrators. An administrator adds accounts (`Add-LocalGroupMember -Group Bifrost -Member <account>`); membership takes effect at the account's next logon. The daemon accepts only a local group created by an administrator, never an account or a built-in group: a missing or inadmissible group stops the daemon at startup, and `--install-service` refuses to record it. [Document 08](docs/08-coquille-graphique.md) details the rights.

Binaries go into `%ProgramFiles%\Bifrost`. Writable state goes into `%ProgramData%\Bifrost`, whose ownership and inherited permissions are reset to SYSTEM and Administrators. Comparisons use SIDs, not translated account names. A correct-looking ACL is not enough if another account still owns the directory and can rewrite that ACL.

`wireguard.dll` and `dnscrypt-proxy.exe` are not bundled in this repository. `-Pilote` places the WireGuardNT library next to the running daemon; a library beside a development build will not serve a daemon installed elsewhere. `-Resolveur` also records the resolver path in the service command line.

The resolver runs under LocalService (`S-1-5-19`), not SYSTEM. Its configuration directory is readable by that account, and only its `etat` subdirectory is writable. The daemon refuses to use the profile's directory as the resolver's directory, because that would expose the profile's private key to the resolver account.

### Uninstall on Windows

```powershell
Stop-Service BifrostDaemon
& "$env:ProgramFiles\Bifrost\bifrost-daemon.exe" --cleanup-firewall
& "$env:ProgramFiles\Bifrost\bifrost-daemon.exe" --uninstall-service
Remove-Item -Recurse -Force "$env:ProgramFiles\Bifrost"
```

Again, clean the filters before deleting the binary. Stopping the service alone does not disarm the kill switch.

The access group `Bifrost` is not removed. Once the service is uninstalled, an administrator removes it with `Remove-LocalGroup -Name Bifrost`.

## Check file integrity offline

```bash
bifrost-cli prove binaire --fichier ./bifrost-daemon --sha256 <expected-SHA256>
bifrost-cli --json prove binaire --fichier ./bifrost-daemon --sha256 <expected-SHA256>
```

This compares the file's bytes with a SHA-256 supplied separately. It does not contact the daemon or network, request elevation or modify the file. It accepts regular, non-symlink files up to 512 MiB. The report concerns the bytes read, so the file must remain immutable during the check.

Exit codes are 0 for `MATCH`, 1 for `MISMATCH`, and 2 for `UNMEASURED` or invalid CLI syntax. JSON contains the `file-sha256` scope, both hashes and the number of bytes read, not the local filename or path.

A match establishes equality to the supplied hash, not the publisher's identity or the safety of a later execution. Hashes themselves can identify files; review a report before sharing it.

## Compare firewall state

### nftables captures

```bash
bifrost-cli --json prove nft --attendu reference.json --observe capture.json
```

The inputs are JSON captures from `nft -j list ruleset`. The command compares tables, chains, rules, named objects and order without invoking nft or changing rules. It keeps priorities and exceptions, while ignoring handles and changing kernel state such as counters, quota consumption and set-element expiry. Reports do not export the captures' names, addresses, elements or paths.

Files are limited to 2 MiB. Invalid captures and unsupported object types remain `UNMEASURED`. A file-to-file match does not certify the active firewall; either capture could be old or incomplete.

### Active nftables state

On Linux, replace the supplied observation with a read-only collection of the current network namespace:

```bash
bifrost-cli --json prove nft --attendu reference.json --actif
bifrost-cli --json prove nft --politique examples/politique-nft-v1.json --actif
bifrost-cli --json prove nft --politique-daemon --actif
```

The three expected-state sources are distinct:

1. `--attendu`: a capture supplied by the user.
2. `--politique`: an explicit v1 intention, rendered through Bifrost's own policy engine. All seven example fields are required, including explicit `null` values.
3. `--politique-daemon`: the policy the daemon declares it most recently handed to its nftables engine.

Active collection checks the kernel generation around the read. Daemon mode also reads the declaration before and after collection. Unstable state, insufficient rights, unsupported formats, a missing declaration or an unavailable daemon remain `UNMEASURED`, with a reason. The command does not bypass denied access or acquire privileges.

The client requires root peer credentials before asking for the declaration. This identifies the listening account; it does not attest the executable of an arbitrary root process. A match means the observed rules agree with the stated reference, not that every possible traffic path is leak-free.

### Active WFP state

On Windows:

```powershell
bifrost-cli --json prove wfp --politique-daemon --actif
```

The command reads the daemon's declaration, enumerates WFP in a single read-only transaction, then reads the declaration again. It compares Bifrost's provider, sublayer and filters, including arbitration against readable third-party filters at the effective sublayer weight.

For this proof, the named pipe must belong to LocalSystem; a pipe bound under SYSTEM with the daemon's descriptor does belong to LocalSystem (measured on essai-windows on 2026-10-17 through a one-off scheduled task running as SYSTEM). A console daemon, which assigns its pipe to the Administrators group (`O:BA`), is accepted by ordinary commands but not by this proof. Access denied remains `UNMEASURED`, never an empty successful enumeration. Paths, SIDs, LUIDs and GUIDs are not exported in the report.

The complete contracts are in [the local-observation specification](docs/09-souverainete-verifiable.md).

## Compare routing and effective DNS

```bash
bifrost-cli --json prove routes --intention intention.json --actif
bifrost-cli --json prove routes --politique-daemon --actif
```

Routing comparisons are available on Linux and Windows. Both use the same plan-generating functions as the daemon and read the system twice without modifying it. Daemon mode checks its declared plan around collection; intention mode uses a caller-supplied description.

The Linux intention has six mandatory fields, including explicit nulls:

```json
{"schema_version": 1, "chemin": "wireguard", "interface": "wg0", "fwmark": 51820, "table": 51820, "coeur_uid": null}
```

Linux checks the software's rules and their order, earlier third-party rules, the usable tunnel route and routes that can pass before it. It does not prove already cached socket routes, open connections, future changes, firewall behavior or DNS. Connected routes from wide interface masks and link multicast are named scope limits.

The Windows intention has seven mandatory fields:

```json
{"schema_version": 1, "plateforme": "windows", "chemin": "wireguard", "interface": "wg0", "mtu": 1420, "familles": ["ipv4", "ipv6"], "destinations": ["10.0.0.0/8", "fd00::/8"]}
```

Windows reads IP Helper routes, interface rows and addresses. It compares planned routes, route and interface metrics, unexpected tunnel routes and competing routes. Equal effective metrics remain `UNMEASURED`, because this command does not read the tie-break decision.

Effective DNS comparisons are currently Linux-only:

```bash
bifrost-cli --json prove dns --intention intention.json --actif
bifrost-cli --json prove dns --politique-daemon --actif
```

An explicit intention uses these seven fields:

```json
{"schema_version": 1, "backend": "systemd-resolved", "interface": "wg0", "local_resolver": "127.0.0.1", "upstream": ["192.0.2.53", "2001:db8::53"], "embarque": false, "resolveur_uid": null}
```

The command reads `nsswitch.conf`, port-53 UDP listeners, the mode and contents of `/etc/resolv.conf`, and systemd-resolved servers and domains through D-Bus. It checks the expected tunnel DNS scope, other active resolver scopes, LLMNR and the embedded resolver's listener and identity. An unavailable or inconsistent source remains `UNMEASURED`.

In daemon mode, the expected plan is the one the daemon declares, read from its socket before and after collection. That declaration is reserved to root: a member of the `bifrost` group, who has status, receives a refusal that names the command, and the report remains `UNMEASURED`.

Reports contain categories and counts, not local addresses, domains, interfaces or account identities. `.local` through mDNS is a named scope limit, not a silently ignored path. Application-specific resolvers, caches and open connections are outside this comparison. Neither a routing match nor a DNS match is a global VPN-security verdict.

## Test

### CI and platform coverage

Pull requests and pushes to `main` run Linux formatting/lint/tests, the graphical shell's Linux checks (format, build, clippy, tests), the Linux packages of the daemon and of the shell (`.deb` and `.rpm` built and checked, the `.deb` installed then removed on the disposable runner, the daemon `.rpm` installed, refused, reinstalled and removed in Fedora containers on that runner, the shell started once installed), leak checks, dependency auditing and parser fuzzing. Fuzzing replays the seeds, then runs each target for 30 seconds. Every day at 04:37 UTC, a scheduled run executes only the dependency audit (`cargo audit`, `cargo deny`, `cargo vet`) on the latest commit of `main`, with a freshly downloaded RustSec advisory database, so an advisory published against a dependency in any lockfile (root, fuzzing harness, graphical shell) turns it red without waiting for a commit. GitHub may delay scheduled runs and disables them after 60 days without repository activity. New revisions cancel obsolete automatic runs on the same PR or branch.

**Windows validation is manual.** Before a Windows delivery, run it on the revision being delivered through Actions > ci > Run workflow > `windows`, or:

```bash
gh workflow run ci.yml --repo Musyg/bifrost-vpn --ref main -f windows=true
```

That dispatch runs only the four Windows jobs: lint and tests (30-minute limit), the graphical shell (build, clippy and tests, 25-minute limit), the MSI (build, ICE validation, real install, repair and uninstall, 30-minute limit) and the shell's MSI (build, ICE validation, real install, refused elevated start and uninstall, 30-minute limit), each with one active run at a time. The Windows lint-and-test job sets `BIFROST_RUNNER_JETABLE`: on that disposable runner, and only there, a test creates a local group and two accounts, measures the access group's channel (a member commands the daemon through the shell, gets a named refusal for every other command and cannot add a pipe instance; a non-member is refused; the elevated test process keeps the whole channel), measures on that real group what the unit tests of `bifrost-ipc` measure elsewhere on the test account (form and domain of the group, an equivalent form of its SID rendered canonical, the built-in administrator's RID refused, the DACL of the bound pipe: SYSTEM, Administrators and the group, nothing else), and removes them. Elsewhere it reports `SKIPPED` with its reason. The runner's account is a built-in account, so those unit tests report `SKIPPED` there, under one stated reason; the Windows abstention budget expects exactly those lines. A skipped Windows job is not Windows validation. The recorded result must identify the SHA it actually checked.

The MSI job also sets `BIFROST_RUNNER_JETABLE`, on its install step only: the MSI is really installed there (service, `Bifrost` group, rights on `%ProgramData%\Bifrost`, service command line read back from the registry), repaired, then uninstalled, with and without a resolver in place; the `msiexec` logs are kept for 7 days next to the MSI. The `paquets-linux` job sets it on the step that installs the `.deb`, replays the refusal of mixed accounts, then removes and purges it; its container step does not set it, since the daemon `.rpm` is installed there only inside disposable Fedora containers. The shell's jobs set it on their install step only: `paquets-gui-linux` installs its `.deb`, starts the shell as root (refusal expected) then as the runner's user on a virtual X server, and removes it; `paquets-gui-windows` installs its MSI, starts the shell elevated (refusal expected) and uninstalls it, keeping the `msiexec` logs for 7 days.

A pull request that touches `gui/`, `crates/bifrost-coquille`, `crates/bifrost-icone`, `crates/bifrost-ipc` or `packaging/msi` waits, before merging, for a green manual `windows` run on its revision: it is the only run where the shell and the MSI are built on Windows.

### Local commands

```bash
cargo test --workspace
sudo ./scripts/e2e-linux.sh
sudo ./scripts/e2e-linux.sh target/debug --unite packaging/systemd/bifrost-daemon.service
sudo ./scripts/check-strict.sh
sudo ./scripts/packaging-linux.sh
./scripts/paquets-linux.sh
./scripts/paquets-rpm-conteneur.sh
./scripts/paquets-gui-linux.sh
./scripts/resolveur-linux.sh
sudo ./scripts/resolveur-systemd-linux.sh
sudo ./scripts/service-systemd-linux.sh
sudo ./scripts/mort-daemon-systemd-linux.sh
sudo ./scripts/preuve-dns-daemon-linux.sh
./scripts/fuzz-linux.sh
```

The installed-service tests use the real unit, binaries and hardening, with network namespaces and an isolated `/etc` where needed. They do not silently arm a host-wide kill switch on the machine running the tests.

The fuzz harness lives in `fuzz/`, a separate Cargo workspace with its own lockfile, seeds and dependency policy. It needs a nightly toolchain and cargo-fuzz 0.13.2. `--duree N`, `--rejouer` and repeatable `--cible NOM` select duration, seed replay and targets. Harness code is not shipped in the VPN binaries.

On Windows, `scripts/packaging-windows.ps1` tests the installer in a redirected filesystem sandbox but uses the real service manager. It refuses to run over an existing BifrostDaemon service. `scripts/service-windows.ps1` tests the installed service's full connection cycle and needs the Linux peer from `scripts/service-windows-pair.sh`. That full-service test cuts the machine's network and must be run with the documented detached task and cleanup procedure.

### Windows firewall tests

```powershell
.\bifrost-daemon.exe --wfp-selftest
```

This checks filter creation, repeated arming, removal and the daemon's path/user identity. The main kill-switch blocks are converted to permits so ordinary traffic is not cut. Its identity probe uses a narrowly scoped block on a documentation address, with a negative control and a mutated identity.

For the blocking test, use a dedicated machine you do not depend on remotely:

```powershell
.\bifrost-daemon.exe --wfp-selftest-blocking
```

It cuts the machine's network while it runs and is not included in CI, since it would also cut the runner's connection to GitHub. `--cleanup-firewall` removes the ordinary armed filters if a test is interrupted.

### What a test result means

The Linux leak harness covers DNS, DoH-policy bypass, exit IP, IPv6, abrupt tunnel loss, reconnection, startup, the transport-core exemption, the encrypted-resolver exemption and daemon death. It builds two network namespaces, establishes a real WireGuard tunnel, injects faults and judges packet captures.

Every measurable vector first checks that its probe really leaks without protection, then checks that protection stops it. A silent control is not a successful protection test.

The installed Linux service does not have `CAP_SYS_ADMIN`. Through that service, `check` reports the nine namespace-based vectors as `SKIPPED`, explains why and names the command to run outside the service:

```bash
sudo bifrost-daemon --run-checks
```

`doh-bypass` can still run through the service because it reads policy files. On Windows, `check` runs that policy check and refers the other vectors to dedicated commands. Coverage is not silently transferred from one platform to another.

`check-strict.sh` requires every leak vector to be `PASSED`. Cargo recipes also distinguish executed checks from abstentions: `recettes-strict.sh` exposes `SKIPPED` reasons, and `abstentions-budget.sh` checks them against the platform's explicit allowlist. A newly skipped check makes CI fail rather than disappear into a green Cargo count.

The standalone `e2e-linux.sh` recipe remains manually runnable. CI instead covers its tunnel-establishment and abrupt-loss checks through `exit-ip` and `kill-switch-on-drop`, avoiding the documented GitHub-runner orphan-process cleanup problem.

## Telemetry controls

### DNS filtering

Bifrost uses the optional embedded dnscrypt-proxy resolver to reject telemetry names before their requests enter the tunnel. The rules are maintained in this repository, with a reason and source for each entry.

| Profile | Rejected names | Preserved services |
|---|---|---|
| `equilibre` | Dedicated telemetry, experimentation and advertising names | Windows Update, Store, Defender, activation, connectivity checks and certificates |
| `strict` | The above plus names also carrying content or configuration, such as Spotlight/MSN, push notifications and Office telemetry | The same preserved services |
| `aucun` | No telemetry list | Default behavior |

Select the profile with `dns.anti_telemetrie`. Requesting a telemetry list without the embedded resolver is a validation error, not a setting that silently does nothing. A third "paranoid" profile that would disable updates and activation is not shipped.

Tests interpret each blocking pattern and check that it cannot cover the named baseline services. The resolver self-test asks the running resolver both a blocked telemetry question and an allowed control question in the same run.

Name filtering does not cover hardcoded IP addresses or an application using its own DoH resolver.

### Registry, services and scheduled tasks

Windows-only, with changes made at their source rather than by filtering a resulting connection:

```bash
bifrost-daemon --telemetrie-etat --telemetrie-profil strict
bifrost-daemon --telemetrie-appliquer --telemetrie-profil strict
bifrost-daemon --telemetrie-restaurer
```

The catalogue documents two profiles, source dates and the effects of each setting. Apply records the original state, writes the setting and reads it back. Restore distinguishes a previously absent value from a previously absent key. Missing targets are reported as inapplicable.

The daemon refuses HKCU settings when it runs as SYSTEM: in that context HKCU is SYSTEM's hive, not the user's. The independent Windows recipe reads the targets itself before and after an apply/restore cycle.

On Home and Pro, Microsoft's `AllowTelemetry=0` is treated as 1. These settings do not claim to eliminate Required telemetry. Automatic drift repair after feature updates and a system restore point remain separate work.

### WFP network filtering

```bash
bifrost-daemon --telemetrie-reseau-etat --telemetrie-profil strict
bifrost-daemon --telemetrie-reseau-appliquer --telemetrie-profil strict
bifrost-daemon --telemetrie-reseau-retirer
```

These filters have their own persistent provider and sublayer, separate from the kill switch. Removal uses fixed keys and tolerates missing filters so that it also works after a crash or profile change.

**Filter presence and filter effect are different measurements.** The service-SID mechanism blocks controlled witness services, but DiagTrack and DoSvc escaped the catalogue's filters in the recorded tests. WFP evaluates the token captured when a socket is created; a service impersonating a client can create a socket whose captured token does not carry its service SID. Windows' own service-specific firewall rule reproduced the same behavior.

The catalogue therefore records per-target effects and provenance. In that recorded catalogue, two targets have a measured lack of effect and eight have no measured blocking effect. The strong blocking counts from the method tests belong to controlled witnesses, not those ten targets. Service-specific WFP filtering is defense in depth, not the layer supporting a claim that OS telemetry is stopped.

### DoH policy management

The daemon provides explicit policy-management commands on Linux and Windows:

```bash
bifrost-daemon --doh-policy constater
bifrost-daemon --doh-policy poser
bifrost-daemon --doh-policy retirer
```

`constater` only reads and does not require elevation. `poser` and `retirer` change policy and require the corresponding privileges. They are explicit operations, not an automatic side effect of connecting. Their precise policy scope and refusal behavior are in the [policy readers and writers](crates/bifrost-daemon/src/checks/).

## Transport selection and supervision

`bifrost-evasion` carries policy, not network operations. It uses measured network conditions and per-network history to order candidates. Missing observations do not exclude a candidate, and every exclusion has a reason. The policy layer has no operation that can disarm the kill switch.

```bash
bifrost-daemon --sonder-reseau
bifrost-cli inspection-tls
bifrost-cli inspection-tls --annoncer
```

The daemon measures TCP/443, UDP, high ports, captive portals, QUIC and loss. TLS inspection is measured by the unprivileged client against the bundled Mozilla root set, not the machine's locally modified trust store. `--annoncer` explicitly sends a conclusive result to the daemon; a read-only-looking command does not silently change its decisions.

The normal connection path does not probe the network before connecting. It arbitrates among transports the user's profile actually provides; it does not invent a server or transport outside that profile. Profiles can provide several candidates behind one sing-box selector. The selected first candidate comes from that arbitration, not simply the file's order.

VLESS + REALITY and Hysteria2 are carried by sing-box. Xray's current generator only supplies a direct output and is refused for a real profile rather than letting an apparently established tunnel send plaintext traffic. AmneziaWG's UAPI setup is not yet implemented in this path. These are distinct from the real-binary self-tests of third-party cores.

A core-based profile requires both daemon flags `--coeurs-dans` and `--facade`. The kill switch is armed before the core starts, and the core must answer before the TUN interface directs system traffic to it. The TCP/IP forwarding path translates flows into SOCKS5 connections; UDP uses an association whose TCP control connection remains open and monitored.

On Linux, the core escapes its own TUN through identity-based routing. On Windows, its sockets are bound to a physical interface selected before the tunnel's default route is installed. Changing the physical link can make that binding obsolete; the result is a closed failure rather than an unintended open path.

The supervisor observes traffic, asks for a round-trip liveness result when silence needs diagnosis, and switches the sing-box selector on recognized failure signatures. It reads the selector back after requesting a change; an HTTP 204 alone does not prove the output changed. The local SOCKS endpoint, TUN interface and armed kill switch stay in place through the switch. A core process exit is observed and passed through the existing retry path.

Real-data tests have covered a Windows sing-box client reaching Linux exit servers through REALITY and Hysteria2. They use a banner reachable only from the exit server's loopback interface, with controls that make it unreachable when the path is bypassed. The detailed observations, pinned third-party versions and packet traces are in the [French transport section](README.md#objectif-2--ce-qui-est-fait-ce-qui-ne-lest-pas).

### Transport-specific constraints

- REALITY's borrowed TLS destination matters. A certificate flight larger than the tested envelope can make the handshake fail despite correct authentication keys. `--qualifier-dest` compares observed record sizes with a measured reference; it is a diagnostic, not a universal compatibility certificate.
- With the pinned Hysteria2 implementation, a 1280-byte path can reject the initial QUIC datagrams once IP/UDP and obfuscation overhead are included. The QUIC path probe sets DF and reports the measured size constraint rather than expiring without an explanation.
- Historical censorship observations expire. The current survival table became inert on 30 September 2026 and no longer eliminates candidates on stale entries.
- Silence alone is not proof of censorship. Missing probes, local core failures and an ordinary link outage are not recorded as a failed censorship technique.

## Profiles at rest

Profiles contain WireGuard private keys or core authentication credentials. On Linux, plaintext files readable by group or world are refused before reading. Parent-directory write permissions are checked separately because a private file in a replaceable directory can still be redirected to another server.

```bash
bifrost-cli profil sceller --config tunnel.toml
```

Linux uses systemd-creds; Windows uses DPAPI in the sealing account's context, not `CRYPTPROTECT_LOCAL_MACHINE`. For a Windows service, that account is LocalSystem. The credential name is authenticated so that a valid sealed file for another purpose cannot be silently substituted.

Sealing protects stored files, not a process already able to execute code as root/SYSTEM or read the daemon's memory. The sealed profile is tied to the sealing machine/account. TPM resets, a lost systemd credential secret or relevant DPAPI recovery failures can make it unreadable. Keep a recovery copy before deleting plaintext; the command warns and does not delete the only copy itself.

The daemon opens its own profile on demand. Sealing does not give an ordinary client permission to read the key, and connecting does not let that client choose an arbitrary path for the privileged daemon to open.

## Profile signatures and retrieval

A valid tunnel handshake authenticates the server named in a profile. It does not establish who selected that server. Bifrost therefore authenticates externally received profiles before installing them.

```bash
minisign -G -p confiance.pub -s signature.key
minisign -S -s signature.key -t "serie=1" -m tunnel.toml
bifrost-cli profil installer profil-recu.toml
```

The operator's `confiance.pub` is installed once beside the destination profile. There is no hardcoded central operator key: a self-hosting user signs their own server configuration. Installation verifies the adjacent `.minisig` signature before writing the profile in mode 0600.

The implementation accepts prehashed minisign signatures and rejects the legacy form. `serie=N` in the authenticated trusted comment supplies an explicit monotonic version. An older or equal series is rejected, and omitting a series after numbered profiles have been installed is treated as a downgrade. Opening a profile already installed locally does not demand a bootstrap signature on every connection; local storage protections take over.

### Several delivery channels

```bash
bifrost-cli profil recuperer \
  --depuis https://cdn.example/tunnel.toml \
  --depuis https://raw.githubusercontent.com/example/mirror/main/tunnel.toml \
  --depuis /media/usb/tunnel.toml
```

All channels are queried; the highest accepted signed series wins. A bad signature excludes that channel rather than making one poisoned mirror fatal to every other channel. The report distinguishes a silent channel from a suspicious one, even if retrieval succeeds elsewhere.

Retrieval does not install the profile in place; it states the installation command to use next. Network requests have deadlines and body-size limits. HTTP is accepted with a warning: signatures protect authenticity, not the secrecy of the profile or its server address.

The unprivileged HTTP client uses ureq, rustls and aws-lc-rs. The current ClientHello offers the X25519MLKEM768 hybrid key exchange first. A cut, reset or silent hybrid attempt can trigger a classical retry, still using the same certificate verification. That fallback also occurs after a partial response in the HTTP path; an active attacker can therefore force the classical exchange by cutting the first attempt. The TLS-inspection probe retries only if it received no server bytes. JA3/JA4 fingerprint imitation is not implemented by this stack.

### Sharing through a person

```bash
bifrost-cli profil partager tunnel.toml
bifrost-cli profil recuperer --depuis "bifrost1..."
bifrost-cli profil partager tunnel.toml --chiffrer
```

A share string can travel through Telegram, Signal, email, SMS or a QR code. Bifrost does not call the Telegram API or inherit the Telegram application's transport behavior. The versioned format uses unpadded base64url and accepts whitespace introduced by message wrapping.

A plain share link is signed but not encrypted. The profile and server address are encoded, not hidden. With `--chiffrer`, the signed link is encrypted in the age v1 format with a scrypt recipient. The program generates a 24-character Crockford-base32 passphrase, prints it to stderr and prints the link to stdout. **Send the passphrase through a different channel from the link.**

Long channel identifiers are shortened in reports so that a pasted share link is not echoed back in full with its encoded secrets.

## Wintun on Windows

The generic TUN needed for a core-based path is separate from WireGuardNT. It uses `wintun.dll`:

```powershell
bifrost-cli pilote recuperer
```

The client obtains the upstream archive and verifies its pinned SHA-256 before writing anything. The daemon does not download it. DLLs are loaded by absolute path, and every required entry point must resolve before the adapter is used.

Wintun uses shared-memory rings rather than a Unix file descriptor. A dedicated reader thread feeds a bounded channel; it is not placed in Tokio's blocking pool for the lifetime of the tunnel. Shutdown signals the reader, joins it, then ends the Wintun session. Oversized packets are rejected, never silently truncated. The adapter uses a stable GUID, and interface names follow the stricter Linux length rule so that profiles remain portable.

## Measurement scope and open work

On Windows, startup-filter management is implemented separately from ordinary connection filters:

```powershell
bifrost-daemon --demarrage montrer
```

`montrer` only displays the plan. `poser` installs boot-time and persistent filters; `retirer` removes them. The CLI's default startup policy leaves the CGNAT overlay range open so that remote administration can remain reachable. `--demarrage-sans-overlay` closes that exception and can make a remotely administered machine unreachable after reboot. LAN and IPv6 choices are explicit. Review the plan and use a dedicated test machine before applying it; no startup filter is installed by the commands shown in the quick start.

The daemon, its firewall rules, installed-service behavior, packet paths and local comparison commands have separate tests. Their results should be read at that scope:

- A live WireGuard handshake and a working data path are different checks.
- The recorded Windows blocking test establishes its tested outgoing TCP path, not the ten Linux harness vectors.
- Ordinary armed WFP filters can survive daemon death without establishing protection throughout the pre-BFE boot window. Startup-filter work has its own specification and measurements.
- Linux DHCP clients using `AF_PACKET` sockets can bypass Netfilter; the namespace boundary is the structural containment described in the design.
- A local `MATCH` compares observed state with an explicit reference. It does not attest every traffic path, future state, publisher identity or anonymity.

The open-work register is [ETAT.md](ETAT.md). Further transport integration, telemetry drift handling, GUI work, distribution/update provenance and chaining have their own entries and design documents. No release or test on a different revision is treated as evidence for the current one.

## Documentation

The detailed design and measurement documents are currently in French:

| Document | Scope |
|---|---|
| [ETAT.md](ETAT.md) | Current tasks, next actions and measured test counts |
| [SOTA-2026-07](docs/SOTA-2026-07.md) | MVP dependency versions and their rationale |
| [01: technical architecture](docs/01-architecture-technique.md) | Transport architecture and cryptography |
| [02: kill switch and leak checks](docs/02-killswitch-anti-fuite.md) | WFP, nftables and the reference MVP specification |
| [03: OS telemetry](docs/03-anti-telemetrie-os.md) | Telemetry targets, DNS and Windows control layers |
| [04: DPI and censorship](docs/04-anti-censure-dpi.md) | Transports, selection, switching and measured network behavior |
| [05: anonymity and chaining](docs/05-anonymat-chainage.md) | Threat models, exit architectures, Tor, Nym and correlation |
| [06: software architecture and packaging](docs/06-architecture-logicielle-packaging.md) | IPC, services, planned interface and distribution |
| [07: security programme](docs/07-programme-securite-produit.md) | Threat model, fuzzing, disclosure and regulatory planning |
| [08: graphical shell](docs/08-coquille-graphique.md) | Scope, unprivileged shell, IPC rules, Windows access group, rendering of each state, what is not done |
| [09: local verification](docs/09-souverainete-verifiable.md) | File, firewall, routing and DNS evidence; later verification milestones |

The workspace declares MPL-2.0. Third-party executables are separate dependencies with their own licences. For a security report, follow [SECURITY.md](SECURITY.md), not a public issue containing exploit details or secrets. [packaging/security.txt](packaging/security.txt) carries the RFC 9116 contact information served by the publisher's site.
