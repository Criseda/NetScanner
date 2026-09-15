# NetScanner

![Version](https://img.shields.io/badge/Version-v0.3.0-red)
![Language](https://img.shields.io/badge/Language-0.16.0-orange?logo=zig&logoSize=auto)
![OS](https://img.shields.io/badge/OS-Linux%2C%20MacOS%2C%20Windows-blue)
![License](https://img.shields.io/badge/License-GNU%20GPL--3.0-green)


## 🚀 About

Command-line tool written in Zig for scanning and analyzing local networks

## 📋 Table of Contents

1. ✨ [Usage](#usage)
2. 🔨 [Installation](#installation)
3. ⚙️ [Build](#build)
4. ©️ [License](../LICENSE)

## <a name="usage">✨ Usage</a>

```sh
ns -p <ip> <port-range>    # Scan a single IP address for open ports (example: 192.168.1.1 1-1024)
ns -s <subnet>             # The subnet to scan for IPs in CIDR notation (example: 192.168.0.1/24)
ns --help                  # Display help message
ns --version               # Display version
```

## <a name="installation">🔨 Installation</a>

Requires [Zig](https://ziglang.org/) 0.16.0 or newer (see `build.zig.zon`).

## <a name="build">⚙️ Build </a>

To build for your platform from source

```sh
cd /path/to/repo     # Change to the project directory
zig build            # Build the project
cd ./zig-out/bin/    # Change to the output directory
ns --help            # Run the program
```

To run the tests:

```sh
zig build test --summary all
```

(DEV) to build the cross-platform releases

```sh
cd /path/to/repo
zig build release -Doptimize=ReleaseFast
cd ./zig-out/bin/releases
```

## Branches

`main` is the only long-lived branch. The old `develop` branch was merged
into `main` (stdout fix + README updates) and deleted.
