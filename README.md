# CipherLab 32 - Cryptography & Password Security Toolkit (x86 Assembly)

EL-2003 Computer Organization and Assembly Language Lab, Fall 2026 - Section BDS-3A
NUCES Karachi

**Authors:** Muhammad Zain Abbas (22K-5028), Ghazi Abbas (22K-5041)

A menu-driven console program written in x86 assembly (MASM + Irvine32):
Caesar, Vigenere and XOR ciphers, letter-frequency analysis with automatic Caesar cracking,
a password strength analyser (BSR entropy) and a checksum calculator (djb2 / sum / XOR-fold).

## Contents
- `CipherLab/CipherLab.asm` - source code
- `CipherLab/build.bat`, `CipherLab/.vscode/tasks.json` - build helpers
- `CipherLab/readme.txt` - how to build and use

## Build (Windows)
Install Visual Studio Build Tools 2022 (C++ workload) and the Irvine32 library (`C:\Irvine`), then in the
"x86 Native Tools Command Prompt for VS 2022":

    cd CipherLab
    set IRVINE=C:\Irvine
    build.bat
    CipherLab.exe
