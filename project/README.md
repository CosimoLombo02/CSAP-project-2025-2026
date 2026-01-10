# CSAP Project 2025-2026: Secure File Management System
## Cosimo Lombardi 2031075 CSAP project 2025/2026
## Simone Di Gregorio 2259275 CSAP project 2025/2026

## Overview
This project implements a Client-Server architecture file management, written in C. It features concurrent client handling, user authentication, distinct permission levels (777-style octal), and support for both foreground and background file operations.

**Key Features:**
- **Concurrent Server**: Handles multiple clients simultaneously using `fork()`.
- **Authentication**: Usage of system users and create user directory for each user.
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
| Command | Description | Example | Expected Output |
|---------|-------------|---------|-----------------|
| `login <user>` | Log in as a specific system user. | `login myuser` | `Login successful!` |
| `create_user <user> <permissions>` | Register a new user (creates system user). | `create_user newuser 777` | `User created successfully!` |
| `exit` | Disconnect from the server. | `exit` | `Bye!` |

**Test:** 
1. Run `./client` and type `login <invalid_user>`. Login failed.
2. Type `login <valid_user>`. Login successful.

### File Management
| Command | Description | Example | Expected Output |
|---------|-------------|---------|-----------------|
| `create <path> <perm> [-d]` | Create file or directory (`-d`). | `create file.txt 644`<br>`create mydir 755 -d` | `File created successfully!`<br>`Directory created successfully!` |
| `delete <path>` | Remove a file. | `delete file.txt` | `File deleted successfully!` |
| `cd <path>` | Change server-side directory. | `cd mydir`<br>`cd ..` | `Directory changed successfully!` |
| `list [path]` | List contents of current or specified dir. | `list`<br>`list subfolder` | `drwx... .`<br>`-rw-... file.txt` |
| `move <old> <new>` | Rename or move a file. | `move file.txt newname.txt` | `File moved successfully!` |
| `chmod <path> <perm>` | Change permissions. | `chmod file.txt 777` | `File chmod successfully!` |

**Test:**
1. `create testdir 777 -d` -> `list` (verify existence).
2. `cd testdir` -> `create test.txt 600` -> `list`.
3. `move test.txt renamed.txt` -> `list` (verify rename).
4. `delete renamed.txt` -> `list` (verify deletion).

### I/O Operations
| Command | Description | Example | Expected Output |
|---------|-------------|---------|-----------------|
| `read [-offset=N] <path>` | Read file content. | `read file.txt`<br>`read -offset=10 file.txt` | `Content of the file...` |
| `write [-offset=N] <path>` | Write text to file. | `write file.txt` | `Enter text. Press ENTER and after press Ctrl+D to finish.` |

**Test:**
1. `write file.txt` -> Enter text -> `Enter text. Press ENTER and after press Ctrl+D to finish.`.
2. `read file.txt` -> Verify content matches.

### File Transfer
| Command | Description | Example | Expected Output |
|---------|-------------|---------|-----------------|
| `upload <client_path> <server_path> [-b]` | Upload file to server. `-b` for background. | `upload loc.txt srv.txt`<br>`upload loc.txt srv.txt -b` | `Upload successful`<br>`Background Upload started...` |
| `download <server_path> <client_path> [-b]` | Download file from server. `-b` for background. | `download srv.txt loc.txt`<br>`download srv.txt loc.txt -b` | `Download successful`<br>`Background Download started...` |

**Test:**
1. **Foreground**: `upload local_file.txt .`. Check server lists it. `download . local_file.txt`.
2. **Background**: `upload local_file.txt . -b`. Client should return to prompt after the upload is concluded. Wait for "[Background] ... concluded" message.
3. **Relative Paths**: `cd subdir` -> `upload local.txt . -b`. Verify file ends up in `subdir`.

### User-to-User Transfer
Send a file directly to another online user.

| Command | Description | Example | Expected Output |
|---------|-------------|---------|-----------------|
| `transfer_request <file> <user>` | Request to send a file to `<user>`. | `transfer_request report.pdf alice` | `Request ID <ID> sent to alice. Waiting for accept/reject...` |
| `accept <dir> <id>` | Accept a transfer relative to ID. | `accept downloads 1` | `Transfer accepted!` |
| `reject <id>` | Reject a transfer request. | `reject 1` | `Transfer rejected.` |

**Test:**
1. **User A**: `login userA`.
2. **User B**: `login userB`.
3. **User A**: `transfer_request data.txt userB`.
4. **User B**: Receives notification `[!] Incoming Transfer Request 1 from userA for file data.txt Accept with: accept . 1 Reject with: reject 1`.
5. **User B**: `accept . 1`.
6. Verify `data.txt` appears in User B's current directory.

## Concurrency & Locks

The server uses **POSIX file locking (`fcntl`)** to manage concurrent access to files, ensuring data integrity when multiple clients operate on the same file.

- **Shared Lock (Read Lock)**: Allows multiple clients to read a file simultaneously.
- **Exclusive Lock (Write Lock)**: Ensures only one client can modify a file at a time. Blocks other readers and writers.

| Operation | Lock Type | Behavior |
|-----------|-----------|----------|
| `read`, `download`, `transfer_request` | **Shared** | Multiple clients can perform these operations on the same file concurrently. |
| `write`, `upload`, `delete`, `move`, `chmod` | **Exclusive** | Blocks all other access to the file until completed. |

### Testing Locks (Manual)

You will need **two terminal windows** (Client A and Client B) connected to the same server.

#### Test 1: Write Blocks Read (Exclusive vs Shared)
1. **Client A**: `write file.txt` -> Type some text but **DO NOT** finish (don't press Ctrl+D yet). Client A now holds an Exclusive Lock.
2. **Client B**: `read file.txt`.
3. **Result**: Client B should **hang/wait** and receive an error message.
4. **Client A**: Finish writing (Press Enter, then Ctrl+D).
5. **Result**: Client B can now read the file.

#### Test 2: Transfer Request Locks Source File
1.  **Client A**: `transfer_request file.txt ClientB` (assuming Client B is online).
    - Client A will receive a "Waiting for accept/reject..." message and return to prompt.
2.  **Client A** (in the same terminal): `delete file.txt`.
3.  **Result**: The delete command hangs because `file.txt` is locked by the pending transfer.
4.  **Client B**: `accept . <id>`.
5.  **Result**: The transfer completes, and Client A can delete the file.
