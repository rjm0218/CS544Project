# CS544Project

This is a Go project that implements a client-server application using the QUIC protocol. The server supports user authentication, file uploads, and file downloads. The client can initiate connections with the server, authenticate using a username and password, and perform file transfer operations.

## Features

- User authentication with username and password
- File upload and download functionality
- Error handling and error reporting
- TLS encryption for secure communication

## Project Structure

- `cmd/echo`: Contains the main entry point for the client and server applications.
- `pkg/client`: Implementation of the client-side logic.
- `pkg/server`: Implementation of the server-side logic, including user authentication, file transfer handling, and session management.
- `pkg/pdu`: Defines the protocol data unit (PDU) structures and helper functions for encoding and decoding PDU messages.
- `pkg/util`: Utility functions for generating TLS configurations.
- `local`: Directory representing local files for the client (can upload files from here and downloaded files will be dropped here)
- `repository`: Directory representing the server's files (can upload files to here and downloaded files will be read from here)
- `Makefile`: Makefile used to build echo binary for both client and server

## Configuration

The client and server can be configured using flags during the echo calls below. The following options are available:

- `-tls-gen`: Generate a self-signed TLS certificate (true/false)
- `-cert-file`: Path to the TLS certificate file (if `tls-gen` is false)
- `-key-file`: Path to the TLS key file (if `tls-gen` is false)
- `-server-addr`: Server address or hostname when starting the server (default "localhost")
- `-server-ip`: Server IP address for the client to connect to (default "0.0.0.0")

Port number is hardcoded to 4242

## Usage

1. Build the server and client applications:

make build


2. Run the server:


./bin/echo -server -server-ip `ip`


3. Run the client and connect to the server:


./bin/echo -client -server-addr `address`


4. Follow the prompts in the client to authenticate and perform file transfer operations.


## Login

Hardcoded users for testing purposes are located in `pkg/server/login.go`. The following users are options:

	Username: "user1", Password: "password1!", Permissions: "upload" && "download",
	Username: "user2", Password: "password2!", Permissions: "download",
	Username: "user2", Password: "password3!", Permissions: "upload",

## Protocol Data Units (PDUs)

The project defines several PDU types for communication between the client and server:

- `HANDSHAKE_INIT`: Initiate the handshake process for authentication.
- `HANDSHAKE_RESPONSE`: Server response to the handshake initiation.
- `DATA`: Transfer file data.
- `CONTROL`: Control messages for operations like starting a file transfer, closing the connection, etc.
- `ERROR`: Error messages.
- `ACK`: Acknowledgment messages.