package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"CS544PROJECT/pkg/pdu"
	"CS544PROJECT/pkg/util"

	"github.com/quic-go/quic-go"
)

const (
	adrs       = "localhost:3000"
	repository = "./repository"
)

const (
	MessType = iota
	DATAMess
	ACKMess
	CONMess
	ERRORMess
)

const (
	OptionFlags = iota
	NO_FLAG
	FLAG_SYNC
	FLAG_ASYNC
	FLAG_COMPR
	FLAG_MULTI
	FLAG_VALID
)

const (
	AuthType = iota
	USERPASS
	CERT
)

const (
	ReqOp = iota
	READ
	WRITE
	DELETE
)

const (
	Permissions = iota
	NOPERM
	PERMREAD
	PERMWRITE
	PERMDELETE
)

const (
	AckStatus = iota
	SUCCESS
	RESEND
	FAILURE
)

const (
	TranState = iota
	IDLE
	INITIATING
	UPLOADING
	DOWNLOADING
	DELETING
	COMPLETE
	PAUSED
	ERROR
)

const (
	ErrorCode = iota
	FILENOTFOUND
	DIRNOTFOUND
	ACCESSDENIED
	TIMEOUT
	CONNECTIONINT
	UNKNOWN
)

const (
	ControlCode = iota
	START
	STARTUP
	STARTDOWN
	PAUSEUP
	PAUSEDOWN
	RESUMEUP
	RESUMEDOWN
	STOPUP
	STOPDOWN
	STARTDEL
	RESET
)

type ServerConfig struct {
	GenTLS   bool
	CertFile string
	KeyFile  string
	Address  string
	Port     int
}

type Server struct {
	cfg ServerConfig
	tls *tls.Config
	ctx context.Context
}

func NewServer(cfg ServerConfig) *Server {
	server := &Server{
		cfg: cfg,
	}
	server.tls = server.getTLS()
	server.ctx = context.TODO()
	return server
}

func (s *Server) getTLS() *tls.Config {
	if s.cfg.GenTLS {
		tlsConfig, err := util.GenerateTLSConfig()
		if err != nil {
			log.Fatal(err)
		}
		return tlsConfig
	} else {
		tlsConfig, err := util.BuildTLSConfig(s.cfg.CertFile, s.cfg.KeyFile)
		if err != nil {
			log.Fatal(err)
		}
		return tlsConfig
	}
}

func (s *Server) Run() error {
	address := fmt.Sprintf("%s:%d", s.cfg.Address, s.cfg.Port)
	listener, err := quic.ListenAddr(address, s.tls, nil)
	if err != nil {
		log.Printf("error listening: %s", err)
		return err
	}

	//SERVER LOOP
	for {
		log.Println("Accepting new session")
		sess, err := listener.Accept(s.ctx)
		if err != nil {
			log.Printf("error accepting: %s", err)
			return err
		}

		go s.streamHandler(sess)
	}
}

func (s *Server) streamHandler(sess quic.Connection) {
	for {
		log.Print("[server] waiting for client to open stream")
		stream, err := sess.AcceptStream(s.ctx)
		if err != nil {
			log.Printf("[server] stream closed: %s", err)
			break
		}

		//Handle protocol activity on stream
		s.protocolHandler(stream)
	}
}

func (s *Server) protocolHandler(stream quic.Stream) error {
	buff := pdu.MakePduBuffer()

	// Read the command from the stream
	n, err := stream.Read(buff)
	if err != nil {
		log.Printf("[server] Error Reading Raw Data: %s", err)
		return err
	}

	// Handle handshake messages
	HandHeader, err := pdu.HandMessHeaderFromBytes(buff[:pdu.HandHeadSize])
	if err != nil {
		log.Printf("[server] Error decoding handshake header: %s", err)
		return err
	}

	if HandHeader.Type == pdu.HANDSHAKE_INIT || HandHeader.Type == pdu.HANDSHAKE_RESPONSE {
		return s.handleHandshake(stream, buff[:n])
	}

	// Check if a session token is provided
	sessionToken := strings.TrimSpace(string(buff[:n]))
	user, authenticated := getSession(sessionToken)

	if !authenticated {
		return fmt.Errorf("session not authenticated")
	}

	return s.handleAuthenticatedUser(stream, user, sessionToken)
}

func (s *Server) handleHandshake(stream quic.Stream, raw []byte) error {
	handshakeMessage, err := pdu.HandMessageFromBytes(raw)
	if err != nil {
		log.Printf("[server] Error decoding handshake message: %s", err)
		return err
	}
	s.sendHandAck(stream, handshakeMessage.Header, handshakeMessage.Header.SeqNumber, pdu.INITIATING, pdu.ACK_SUCCESS)
	if handshakeMessage.AuthType == pdu.USER_PASSWORD {
		credentials := strings.SplitN(handshakeMessage.Data, ":", 2)
		if len(credentials) != 2 {
			return fmt.Errorf("invalid credentials format")
		}
		username, password := credentials[0], credentials[1]

		user, authenticated := authenticateUser(username, password)
		if !authenticated {
			log.Printf("[server] Authentication failed for user %s", username)
			return s.sendHandError(stream, handshakeMessage.Header, pdu.ACCESS_DENIED, "Authentication failed")
		}

		sessionToken := createSession(user)
		log.Printf("[server] User %s authenticated with session token %s", username, sessionToken)

		// Send session token back to client
		_, err = stream.Write([]byte(sessionToken))
		if err != nil {
			log.Printf("[server] Error sending session token: %s", err)
			return err
		}

		return nil
	}

	return fmt.Errorf("unsupported authentication type")
}

func (s *Server) handleAuthenticatedUser(stream quic.Stream, user *User, token string) error {
	buff := pdu.MakePduBuffer()

	for {
		// Read the command from the stream
		n, err := stream.Read(buff)
		if err != nil {
			log.Printf("[server] Error Reading Raw Data: %s", err)
			return err
		}

		head_size := pdu.HeaderSize
		header, err := pdu.MessHeaderFromBytes(buff[:head_size])
		if err != nil {
			log.Printf("[server] Error decoding PDU header: %s", err)
			return err
		}

		switch header.Type {
		case pdu.DATA:
			return s.handleData(stream, buff[:n], user)
		case pdu.CONTROL:
			return s.handleControl(stream, buff[:n], token)
		case pdu.ERROR:
			return s.handleError(buff[:n])
		case pdu.ACK:
			return s.handleAck(buff[:n])
		default:
			log.Printf("[server] Unknown PDU type: %d", header.Type)
			return fmt.Errorf("unknown PDU type: %d", header.Type)
		}
	}
}

func (s *Server) handleData(stream quic.Stream, raw []byte, user *User) error {
	dataMessage, err := pdu.DataMessageFromBytes(raw)
	if err != nil {
		log.Printf("[server] Error decoding DataMessage: %s", err)
		return err
	}

	filename := string(dataMessage.Data)
	filepath := filepath.Join(repository, filename)

	switch dataMessage.RequestedOp {
	case pdu.WRITE:
		if authorizeUser(user, "upload") {
			return s.handleUpload(stream, filepath, dataMessage)
		} else {
			return s.sendError(stream, dataMessage.Header, pdu.ACCESS_DENIED, "User does not have permission to upload files")
		}
	case pdu.READ:
		if authorizeUser(user, "download") {
			return s.handleDownload(stream, filepath, dataMessage)
		} else {
			return s.sendError(stream, dataMessage.Header, pdu.ACCESS_DENIED, "User does not have permission to download files")
		}
	default:
		log.Printf("[server] Unknown Requested Operation: %d", dataMessage.RequestedOp)
		return fmt.Errorf("unknown Requested Operation: %d", dataMessage.RequestedOp)
	}
}

func (s *Server) handleUpload(stream quic.Stream, filepath string, dataMessage *pdu.DataMessage) error {
	file, err := os.Create(filepath)
	if err != nil {
		log.Printf("[server] Error Creating File: %s", err)
		s.sendError(stream, dataMessage.Header, pdu.WRITE_ERROR, "Error writing file to server")
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, stream)
	if err != nil {
		log.Printf("[server] Error Writing File Data: %s", err)
		s.sendError(stream, dataMessage.Header, pdu.WRITE_ERROR, "Error writing file to server")
		return err
	}

	log.Printf("[server] File %s uploaded successfully", filepath)
	return s.sendAck(stream, dataMessage.Header, dataMessage.SeqNumber, pdu.COMPLETE, pdu.ACK_SUCCESS)
}

func (s *Server) handleDownload(stream quic.Stream, filepath string, dataMessage *pdu.DataMessage) error {

	_, err := os.Stat(filepath)
	if os.IsNotExist(err) {
		s.sendError(stream, dataMessage.Header, pdu.FILE_NOT_FOUND, "File not found on server")
		return err
	}

	file, err := os.Open(filepath)
	if err != nil {
		log.Printf("[server] Error Opening File: %s", err)
		s.sendError(stream, dataMessage.Header, pdu.READ_ERROR, "File could not be read")
		return err
	}
	defer file.Close()

	_, err = io.Copy(stream, file)
	if err != nil {
		log.Printf("[server] Error Sending File Data: %s", err)
		s.sendError(stream, dataMessage.Header, pdu.READ_ERROR, "Error reading file from server")
		return err
	}

	log.Printf("[server] File %s downloaded successfully", filepath)
	return s.sendAck(stream, dataMessage.Header, dataMessage.SeqNumber, pdu.COMPLETE, pdu.ACK_SUCCESS)
}

func (s *Server) handleControl(stream quic.Stream, raw []byte, token string) error {
	controlMessage, err := pdu.ControlMessageFromBytes(raw)
	if err != nil {
		log.Printf("[server] Error decoding ControlMessage: %s", err)
		return err
	}

	log.Printf("[server] Control action requested: %d", controlMessage.ControlCode)
	switch controlMessage.ControlCode {
	case pdu.START:
		return s.sendAck(stream, controlMessage.Header, controlMessage.Header.SeqNumber, pdu.INITIATING, pdu.ACK_SUCCESS)
	case pdu.START_UPLOAD:
		return s.sendAck(stream, controlMessage.Header, controlMessage.Header.SeqNumber, pdu.UPLOADING, pdu.ACK_SUCCESS)
	case pdu.START_DOWNLOAD:
		return s.sendAck(stream, controlMessage.Header, controlMessage.Header.SeqNumber, pdu.DOWNLOADING, pdu.ACK_SUCCESS)
	case pdu.CLOSE_CONNECTION:
		deleteSession(token)
		return s.sendAck(stream, controlMessage.Header, controlMessage.Header.SeqNumber, pdu.CLOSE_CONNECTION, pdu.ACK_SUCCESS)
	default:
		log.Printf("[server] Unknown Control Code: %d", controlMessage.ControlCode)
		return s.sendError(stream, controlMessage.Header, pdu.INVALID_CONTROL_CODE, "Unknown Control Code")
	}
}

func (s *Server) handleError(raw []byte) error {
	errorMessage, err := pdu.ErrorMessageFromBytes(raw)
	if err != nil {
		log.Printf("[server] Error decoding ErrorMessage: %s", err)
		return err
	}

	log.Printf("[server] Error received: %s", errorMessage.ErrorMessage)
	return nil
}

func (s *Server) handleAck(raw []byte) error {
	ackMessage, err := pdu.AckMessageFromBytes(raw)
	if err != nil {
		log.Printf("[server] Error decoding AckMessage: %s", err)
		return err
	}

	log.Printf("[server] ACK received for sequence number: %d", ackMessage.AcknowledgedSequenceNumber)
	return nil
}

func (s *Server) sendAck(stream quic.Stream, header pdu.MessHeader, seqNumber uint32, state uint8, status uint8) error {
	ackHeader := pdu.MessHeader{
		Type:          pdu.ACK,
		TransactionID: header.TransactionID,
		SeqNumber:     header.SeqNumber,
		Length:        pdu.HeaderSize + pdu.AckSize, // Adjust as necessary
	}
	ackMessage := pdu.NewAckMessage(ackHeader, uint64(time.Now().Unix()), seqNumber, state, status)
	ackBytes, err := pdu.AckMessageToBytes(ackMessage)
	if err != nil {
		log.Printf("[server] Error encoding AckMessage: %s", err)
		return err
	}

	_, err = stream.Write(ackBytes)
	if err != nil {
		log.Printf("[server] Error sending ACK: %s", err)
		return err
	}
	return nil
}

func (s *Server) sendHandAck(stream quic.Stream, header pdu.HandMessHeader, seqNumber uint32, state uint8, status uint8) error {
	ackHeader := pdu.MessHeader{
		Type:          pdu.ACK,
		TransactionID: header.TransactionID,
		SeqNumber:     header.SeqNumber,
		Length:        pdu.HeaderSize + pdu.AckSize, // Adjust as necessary
	}
	ackMessage := pdu.NewAckMessage(ackHeader, uint64(time.Now().Unix()), seqNumber, state, status)
	ackBytes, err := pdu.AckMessageToBytes(ackMessage)
	if err != nil {
		log.Printf("[server] Error encoding AckMessage: %s", err)
		return err
	}

	_, err = stream.Write(ackBytes)
	if err != nil {
		log.Printf("[server] Error sending ACK: %s", err)
		return err
	}
	return nil
}

func (s *Server) sendHandError(stream quic.Stream, header pdu.HandMessHeader, errorCode uint8, errorMessage string) error {
	errorHeader := pdu.MessHeader{
		Type:          pdu.ERROR,
		TransactionID: header.TransactionID,
		SeqNumber:     header.SeqNumber,
		Length:        pdu.HeaderSize + pdu.ErrSize + uint32(len(errorMessage)),
	}
	errorMsg := pdu.NewErrorMessage(errorHeader, uint64(time.Now().Unix()), errorCode, errorMessage)
	errorBytes, err := pdu.ErrorMessageToBytes(errorMsg)
	if err != nil {
		log.Printf("[server] Error encoding ErrorMessage: %s", err)
		return err
	}

	_, err = stream.Write(errorBytes)
	if err != nil {
		log.Printf("[server] Error sending ErrorMessage: %s", err)
		return err
	}
	return nil
}

func (s *Server) sendError(stream quic.Stream, header pdu.MessHeader, errorCode uint8, errorMessage string) error {
	errorHeader := pdu.MessHeader{
		Type:          pdu.ERROR,
		TransactionID: header.TransactionID,
		SeqNumber:     header.SeqNumber,
		Length:        pdu.HeaderSize + pdu.ErrSize + uint32(len(errorMessage)), // Adjust if change in error message
	}
	errorMsg := pdu.NewErrorMessage(errorHeader, uint64(time.Now().Unix()), errorCode, errorMessage)
	errorBytes, err := pdu.ErrorMessageToBytes(errorMsg)
	if err != nil {
		log.Printf("[server] Error encoding ErrorMessage: %s", err)
		return err
	}

	_, err = stream.Write(errorBytes)
	if err != nil {
		log.Printf("[server] Error sending ErrorMessage: %s", err)
		return err
	}
	return nil
}
