# MemModder 🔍

A simple Windows memory scanner and modifier tool written in C++. Scan process memory for specific values and modify them in real-time.

## ✨ Features

- List Running Processes and PIDs
- Memory scanning for integer values
- Memory writing at specific addresses

## 🚀 Quick Start

### Prerequisites
- Windows 10/11
- MinGW-w64 compiler

### Installation

1. **Download MinGW-w64**:
   - Visit [MinGW-w64 Binaries](https://github.com/niXman/mingw-builds-binaries/releases)
   - Download: `x86_64-15.1.0-release-posix-seh-ucrt-rt_v12-rev0.7z`

2. **Setup**:
   ```bash
   # Extract mingw64 folder to C:\mingw64
   # Add C:\mingw64\bin to PATH
   # Restart IDE/terminal
   ```

3. **Build & Run**:
   ```bash
   mingw32-make
   .\build\main.exe
   ```

## 📖 Usage

| Command | Description |
|---------|-------------|
| `[number]` | Scan for integer value |
| `show` | Display found addresses |
| `write` | Write value to address |
| `new` | Start new scan |
| `exit` | Exit application |

