# Kali Linux layout, packages, and the live toolchain probe

`cyberpowerfull` does not ship binaries, wordlists, or templates. It reads what is installed on
the host and plans against that. This document records the layout it expects, the package that
provides each capability, and how to verify the result before an engagement.

## What the probe reads

| Source | Used for |
|---|---|
| `PATH` (via `shutil.which`) | binary presence, alternate names (`httpx-toolkit`, `testssl.sh`, `nxc`) |
| `<binary> --version` / `-version` | version banner in `--toolchain` / `--doctor` |
| `/usr/share/wordlists`, `/usr/share/seclists`, `/usr/share/dirb`, `/usr/share/wfuzz`, … | wordlist discovery (kind + size + compression flag) |
| `/usr/share/nuclei-templates`, `~/nuclei-templates`, `~/.local/nuclei-templates` | template count and `--templates` listing |
| `/usr/share/nmap/scripts` | NSE script count and `--nse` listing |
| `/usr/share/exploitdb` + `searchsploit` | offline Exploit-DB queries |
| `/usr/share/sniper/loot`, `~/loot`, `./loot` | Sn1per workspace parsing |
| `/etc/os-release`, `platform` | host fingerprint in the inventory |

Nothing is cached to disk. `--toolchain` reflects the machine at the moment it runs.

## Install the core set

```bash
sudo apt update
sudo apt install -y \
  nmap masscan naabu subfinder amass dnsrecon \
  httpx-toolkit katana ffuf gobuster feroxbuster whatweb wafw00f nikto nuclei \
  sqlmap dalfox arjun wpscan testssl.sh sslscan \
  hydra john hashcat exploitdb wordlists seclists
```

Then refresh the template repository:

```bash
nuclei -update-templates            # or: sudo apt install nuclei-templates
```

Kali renames two binaries that other distributions ship under the ProjectDiscovery name:

| Tool in this project | Kali binary | Why the rename |
|---|---|---|
| `httpx` | `httpx-toolkit` | avoids clashing with the Python `httpx` package |
| `testssl` | `testssl.sh` | upstream script name |

The wrapper resolves both automatically: `binary_alternatives` is tried in order and the
resolved name is recorded in the tool catalogue and the trace.

## Wordlists

Kali keeps wordlists under `/usr/share/wordlists`; the `seclists` package adds ~1.8 GB under
`/usr/share/seclists` with a symlink from the former.

- `rockyou.txt` ships compressed as `rockyou.txt.gz`. Compressed files are reported by
  `--wordlists` but never handed to a fuzzer.
- Discovery wordlists are resolved by preference (`raft-medium-directories`, `common.txt`,
  `directory-list-2.3-medium`), then by size. If none match, the step is skipped — a playbook
  does not invent a path.
- Credential testing refuses lists longer than the configured candidate cap
  (`max_password_candidates`, default 500, hard maximum 5000).

```bash
cyberpowerfull --wordlists                  # everything discovered
cyberpowerfull --wordlists discovery        # what content discovery would use
cyberpowerfull --wordlists --json | jq '.[0:5]'
```

## Readiness check before an engagement

```bash
cyberpowerfull --doctor --scope scope.json --target app.example.test
```

It reports, in one pass:

1. scope validity, fingerprint, granted capabilities, and whether the target is in scope;
2. installed vs missing binaries, with versions for the common six;
3. the wordlist resolved for each kind;
4. nuclei template count and path, NSE script count, Exploit-DB presence;
5. availability of Strix / PentAGI / Sn1per;
6. local model health.

Exit code `5` means the model is unreachable (playbooks still work). Missing binaries are not an
error: they are the honest state of the host and every affected step is skipped with a reason.

## Minimal hosts

The native `tcp_probe` connector needs no binary at all, so a minimal image still produces real
evidence:

```bash
cyberpowerfull --scope scope.json --target 127.0.0.1 --playbook network
```

This is also what the CI smoke job exercises, so the no-binary path stays working.

## Notes on scope and aggressiveness

- `masscan` and `naabu` require the `aggressive` capability. On a shared or production network,
  leave it out of `scope.json`; the worker layer blocks the tool before argv construction.
- `hydra` requires `credential_testing`. The wrapper caps tasks at 8, stops on the first valid
  credential, refuses oversized lists, and redacts the recovered password in evidence.
- `sn1per`, `strix`, and `pentagi` require `external_agents`. They run their own tooling and
  their own LLM; the adapter still checks that the target is in scope and injects a scope
  statement into the delegated instruction.
