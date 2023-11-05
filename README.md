This project provides a tool for recovering files from FAT32 file systems. It is designed to be a practical utility for retrieving lost or deleted data.

## Features
- Recovery of deleted files from FAT32 file systems.
- Analysis of FAT32 structures to locate lost data.
- User-friendly command-line interface.

## Getting Started

### Prerequisites
- Ensure you have a C compiler installed (e.g., `gcc` or `clang`).
- Knowledge of FAT32 file system is beneficial for using this tool effectively.

### Compilation
To compile the tool, run the following command in the root directory of the project:

```sh
gcc -o fat32_recovery nyufile.c
```

### Usage
After compilation, you can run the program using:

```sh
./fat32_recovery [options]
```
