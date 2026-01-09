# CSAP Project 2025-2026: Secure File Management System
## Cosimo Lombardi 2031075 CSAP project 2025/2026
## Simone Di Gregorio 2259275 CSAP project 2025/2026

## Overview
This project implements a Client-Server architecture for secure file management, written in C. It features concurrent client handling, user authentication, distinct permission levels (777-style octal), and support for both foreground and background file operations.

**Key Features:**
- **Concurrent Server**: Handles multiple clients simultaneously using `fork()`.
- **Authentication**: Usage of system users for secure access and permission enforcement.
- **File Operations**: Create, Read, Write, Delete, Move, and List files/directories.
- **Permissions**: `chmod` support and verification based on standard Linux permissions.
- **Transfers**: Upload and Download (support for background `-b` execution).
- **User-to-User Transfer**: Direct file sharing between logged-in users.

## Prerequisites
- Linux Environment
- GCC Compiler
- permissions to run with `sudo` (required for server to handle user impersonation)

## Compilation
A build script is provided to compile both `server` and `client` executables.

```bash
./build.sh
```

## Usage

### 1. Start the Server
The server requires `sudo` privileges to switch UIDs for user impersonation.
```bash
# Syntax: sudo ./server <root_storage_dir> <ip_address> <port>
sudo ./server home 127.0.0.1 8080
```
- `<root_storage_dir>`: The directory where all user files will be stored (e.g., `home`).
- `<ip_address>`: Bind address (e.g., `127.0.0.1` for localhost).
- `<port>`: Service port (e.g., `8080`).

### 2. Start the Client
Open a new terminal for each client.
```bash
# Syntax: ./client <server_ip> <port>
./client 127.0.0.1 8080
```

## Command Reference & Testing Guide

Once connected, use the following commands.

### User Management
| Command | Description | Example |
|---------|-------------|---------|
| `login <user>` | Log in as a specific system user. | `login myuser` |
| `create_user <user> <pass>` | Register a new user (creates system user). | `create_user newuser 1234` |
| `exit` | Disconnect from the server. | `exit` |

**Test:** 
1. Run `./client` and type `login invalid`. Expect error.
2. Type `login <valid_user>`. Expect success prompt `<valid_user> >`.

### File Management
| Command | Description | Example |
|---------|-------------|---------|
| `create <path> <perm> [-d]` | Create file or directory (`-d`). | `create file.txt 644`<br>`create mydir 755 -d` |
| `delete <path>` | Remove a file or directory. | `delete file.txt` |
| `cd <path>` | Change server-side directory. | `cd mydir`<br>`cd ..` |
| `list [path]` | List contents of current or specified dir. | `list`<br>`list subfolder` |
| `move <old> <new>` | Rename or move a file. | `move file.txt newname.txt` |
| `chmod <path> <perm>` | Change permissions. | `chmod file.txt 777` |

**Test:**
1. `create testdir 777 -d` -> `list` (verify existence).
2. `cd testdir` -> `create test.txt 600` -> `list`.
3. `move test.txt renamed.txt` -> `list` (verify rename).
4. `delete renamed.txt` -> `list` (verify deletion).

### I/O Operations
| Command | Description | Example |
|---------|-------------|---------|
| `read <path> [-offset=N]` | Read file content (partial support). | `read file.txt`<br>`read file.txt -offset=10` |
| `write <path> [-offset=N]` | Write text to file (interactive). | `write file.txt` |

**Test:**
1. `write file.txt` -> Enter text -> `END` (to finish).
2. `read file.txt` -> Verify content matches.

### File Transfer
| Command | Description | Example |
|---------|-------------|---------|
| `upload <local> <server> [-b]` | Upload file to server. `-b` for background. | `upload loc.txt srv.txt`<br>`upload loc.txt srv.txt -b` |
| `download <server> <local> [-b]` | Download file from server. `-b` for background. | `download srv.txt loc.txt`<br>`download srv.txt loc.txt -b` |

**Test:**
1. **Foreground**: `upload local_file.txt server_file.txt`. Check server lists it. `download server_file.txt down_file.txt`. Diff files.
2. **Background**: `upload local_file.txt server_file.txt -b`. Client should immediately return prompt. Wait for "[Background] ... concluded" message.
3. **Relative Paths**: `cd subdir` -> `upload local.txt . -b`. Verify file ends up in `subdir`.

### User-to-User Transfer
Send a file directly to another online user.

| Command | Description | Example |
|---------|-------------|---------|
| `transfer_request <file> <user>` | Request to send a file to `<user>`. | `transfer_request report.pdf alice` |
| `accept <dir> <id>` | Accept a transfer relative to ID. | `accept downloads 1` |
| `reject <id>` | Reject a transfer request. | `reject 1` |

**Test:**
1. **User A**: `login userA`.
2. **User B**: `login userB`.
3. **User A**: `transfer_request data.txt userB`.
4. **User B**: Receives notification `[TRANSFER] Request ID 1 from userA`.
5. **User B**: `accept . 1`.
6. Verify `data.txt` appears in User B's current directory.
