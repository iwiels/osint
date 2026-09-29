## WraithOSINT

A desktop OSINT forensics platform: a headless Python engine and an Electron console,
with a SHA-256 hash-chained chain of custody, a knowledge graph, and a multi-provider
AI investigator.

### Download

| Platform | File | Notes |
|---|---|---|
| **Windows** (x64) | `WraithOSINT-<version>-win-x64-setup.exe` | Per-user installer, no admin rights needed |
| **macOS** (Intel) | `WraithOSINT-<version>-mac-x64.dmg` or `.zip` | Not signed or notarized yet |
| **macOS** (Apple Silicon) | `WraithOSINT-<version>-mac-arm64.dmg` or `.zip` | Not signed or notarized yet |
| **Linux** (x64) | `WraithOSINT-<version>-linux-x64.AppImage` or `.deb` | Portable AppImage or Debian package |

Python is not required: the engine ships inside the app. Your cases, dossiers, and
ledger key live outside the app bundle, so they survive updates.

### First launch

- **Windows:** the installer is not code-signed yet, so SmartScreen may show a warning.
  Choose **More info → Run anyway**.
- **macOS:** the app is not notarized yet. Open it once, then allow it in
  **System Settings → Privacy & Security** (**Open Anyway**).
- **Linux:** make the AppImage executable with `chmod +x`, or install the package with
  `sudo apt install ./WraithOSINT-<version>-linux-x64.deb`.

### Responsible use

WraithOSINT collects open-source information and includes dual-use capabilities. Use it
only with a lawful basis and a legitimate purpose, and read
[LEGAL.md](https://github.com/iwiels/osint/blob/main/LEGAL.md) before use.
Report vulnerabilities as described in
[SECURITY.md](https://github.com/iwiels/osint/blob/main/SECURITY.md).

---

