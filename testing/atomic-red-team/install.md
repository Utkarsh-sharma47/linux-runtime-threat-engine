# Installing the Atomic Red Team lab (user-scoped, no sudo)

Verified on 2026-11-13 on Ubuntu 24.04.5 LTS, kernel 7.0.0-38-generic, x86_64, as a
normal user without `sudo`. Installing the tooling and test definitions executes no
Atomic test.

| Component | Version | Location | Source |
|---|---|---|---|
| PowerShell (`pwsh`) | 7.6.6 LTS | `~/.local/opt/microsoft/powershell/7.6.6`, symlink `~/.local/bin/pwsh` | Official GitHub release archive |
| Invoke-AtomicRedTeam | 2.3.0 | `~/.local/share/powershell/Modules/Invoke-AtomicRedTeam/2.3.0` | PowerShell Gallery (publisher Red Canary) |
| powershell-yaml | 0.4.12 | `~/.local/share/powershell/Modules/powershell-yaml/0.4.12` | PowerShell Gallery (Cloudbase) |
| Atomic test definitions | commit `a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6` | `~/AtomicRedTeam/atomics` (module default) | `github.com/redcanaryco/atomic-red-team` |

Nothing is installed inside this repository; only the lab scripts and docs live here.

## 1. PowerShell 7 from the official binary archive

Microsoft documents a `tar.gz` install for Linux
([install-other-linux](https://learn.microsoft.com/en-us/powershell/scripting/install/install-other-linux)).
Its example extracts to `/opt` with `sudo`; extracting to `~/.local` instead needs no
root and changes nothing system-wide. Ubuntu 24.04 already ships the runtime libraries
it needs (`libicu74`, `libssl3`).

```bash
cd /tmp
curl -fsSL -o pwsh-7.6.6.tar.gz \
  https://github.com/PowerShell/PowerShell/releases/download/v7.6.6/powershell-7.6.6-linux-x64.tar.gz
curl -fsSL -o pwsh-hashes.sha256 \
  https://github.com/PowerShell/PowerShell/releases/download/v7.6.6/hashes.sha256

# Verify: the release hash file is UTF-16; both sources must list the same SHA-256.
sha256sum pwsh-7.6.6.tar.gz
# ddbc4a2d113bbd46d283cfedcbcd117a70caefd7673f41f2b4e0000badf103bc  (GitHub asset digest)
iconv -f utf-16 -t utf-8 pwsh-hashes.sha256 | grep linux-x64.tar.gz

mkdir -p ~/.local/opt/microsoft/powershell/7.6.6 ~/.local/bin
tar zxf pwsh-7.6.6.tar.gz -C ~/.local/opt/microsoft/powershell/7.6.6
chmod +x ~/.local/opt/microsoft/powershell/7.6.6/pwsh
ln -sfn ~/.local/opt/microsoft/powershell/7.6.6/pwsh ~/.local/bin/pwsh
rm pwsh-7.6.6.tar.gz pwsh-hashes.sha256

pwsh --version            # PowerShell 7.6.6
```

`~/.local/bin` is on `PATH` in Ubuntu's default `~/.profile` (log in again if it is not).
The GitHub API also reports the expected digest:
`curl -fsSL https://api.github.com/repos/PowerShell/PowerShell/releases/tags/v7.6.6`.

## 2. Invoke-AtomicRedTeam (CurrentUser scope)

The official wiki
([Installing Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam/wiki/Installing-Invoke-AtomicRedTeam))
documents `Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser`.
It also offers `IEX (IWR '...install-atomicredteam.ps1')`, which pipes a remote script
into the shell; this lab does not use that path. Inspect the gallery metadata first,
then install pinned versions:

```bash
pwsh -NoProfile -Command 'Find-Module -Name invoke-atomicredteam,powershell-yaml -Repository PSGallery |
  Select-Object Name,Version,Author,CompanyName,ProjectUri | Format-List'

pwsh -NoProfile -Command '
Install-Module -Name powershell-yaml -RequiredVersion 0.4.12 -Repository PSGallery -Scope CurrentUser -Force
Install-Module -Name invoke-atomicredteam -RequiredVersion 2.3.0 -Repository PSGallery -Scope CurrentUser -Force'
```

`-Force` only answers the "untrusted repository" prompt non-interactively. PSGallery's
`InstallationPolicy` stays `Untrusted` (check with `Get-PSRepository PSGallery`).

Verify:

```bash
pwsh -NoProfile -Command 'Get-Module -ListAvailable invoke-atomicredteam,powershell-yaml |
  Select-Object Name,Version,ModuleBase | Format-List'
pwsh -NoProfile -Command 'Import-Module invoke-atomicredteam; (Get-Command -Module invoke-atomicredteam).Name'
```

## 3. Atomic test definitions (YAML only)

`Invoke-AtomicTest` reads `$HOME/AtomicRedTeam/atomics` by default on Linux. The wiki's
`-noPayloads` option means "test definitions only, no `/src` or `/bin` payloads"; the
same result with plain `git` from the official repository (a shallow, blob-filtered,
sparse checkout, 67 MB):

```bash
cd ~
git clone --depth 1 --filter=blob:none --no-checkout \
  https://github.com/redcanaryco/atomic-red-team.git AtomicRedTeam
cd AtomicRedTeam
git sparse-checkout init --no-cone
printf '/atomics/**/*.yaml\n/atomics/**/*.md\n/atomics/Indexes/\n/LICENSE.txt\n/README.md\n' \
  > .git/info/sparse-checkout
git checkout -q master
git rev-parse HEAD        # record this commit in your test reports
```

If an approved test needs a payload from `atomics/<T#>/src` or `bin`, add only that path
to `.git/info/sparse-checkout`, review the file, then run `git checkout -q master` again.
Update later with `git -C ~/AtomicRedTeam pull --depth 1` and rebuild the catalog.

## 4. Verify the lab

```bash
testing/atomic-red-team/scripts/preflight.sh
.venv/bin/python testing/atomic-red-team/scripts/catalog.py build \
  --markdown testing/atomic-red-team/test-catalog.md
```

Expected: every preflight line `PASS` (the engine check is `WARN` until `--db` is given)
and `435 Linux tests in 122 techniques` for this atomics commit.

## Uninstall

```bash
pwsh -NoProfile -Command 'Uninstall-Module invoke-atomicredteam; Uninstall-Module powershell-yaml'
rm -rf ~/AtomicRedTeam ~/.local/opt/microsoft/powershell/7.6.6 ~/.local/bin/pwsh
```
