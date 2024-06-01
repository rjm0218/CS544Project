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

## Usage

1. Build the server and client applications:



go build ./cmd/echo


2. Run the server:


./echo -server


3. Run the client and connect to the server:


./echo -client


4. Follow the prompts in the client to authenticate and perform file transfer operations.

## Login

Hardcoded users for testing purposes are located in `pkg/server/login.go`. The following users are options:

	Username: "user1", Password: "password1!", Permissions: "upload" && "download",
	Username: "user2", Password: "password2!", Permissions: "download",
	Username: "user2", Password: "password3!", Permissions: "upload",


## Configuration

The server can be configured using the `ServerConfig` struct in `pkg/server/server.go`. The following options are available:

- `GenTLS`: Generate a self-signed TLS certificate (true/false)
- `CertFile`: Path to the TLS certificate file (if `GenTLS` is false)
- `KeyFile`: Path to the TLS key file (if `GenTLS` is false)
- `Address`: Server IP address or hostname
- `Port`: Server port number

## Protocol Data Units (PDUs)

The project defines several PDU types for communication between the client and server:

- `HANDSHAKE_INIT`: Initiate the handshake process for authentication.
- `HANDSHAKE_RESPONSE`: Server response to the handshake initiation.
- `DATA`: Transfer file data.
- `CONTROL`: Control messages for operations like starting a file transfer, closing the connection, etc.
- `ERROR`: Error messages.
- `ACK`: Acknowledgment messages.