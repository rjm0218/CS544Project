package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"CS544PROJECT/pkg/pdu"
	"CS544PROJECT/pkg/util"

	"github.com/quic-go/quic-go"
)

const (
	adrs       = "localhost:3000"
	repository = "./repository/"
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

// structure to hold a file upload in progress
type FileUpload struct {
	Filename   []byte
	Buffer     []byte
	LastSeqNum uint32
}

// structure to track all the file uploads in progress
var uploads = make(map[uint32]*FileUpload)

// create a new server instance
func NewServer(cfg ServerConfig) *Server {
	server := &Server{
		cfg: cfg,
	}
	server.tls = server.getTLS()
	server.ctx = context.TODO()
	return server
}

// get the TLS configuration for the server
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

// run the server and wait for a session to be initiated
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

// handle a nession session and wait for the client to initiate a stream
func (s *Server) streamHandler(sess quic.Connection) {
	for {
		log.Print("[server] waiting for client to open stream")
		stream, err := sess.AcceptStream(s.ctx)
		if err != nil {
			log.Printf("[server] stream closed: %s", err)
			break
		}

		//Handle protocol activity on stream
		handError := s.protocolHandler(stream)
		if handError == nil {
			return
		} else {
			log.Printf("[server] error handling protocol activity: %s", handError)
			break
		}
	}
}

// handle the protocol activity on a stream including setting up handshake and data
func (s *Server) protocolHandler(stream quic.Stream) error {
	buff := pdu.MakePduBuffer()

	// Read the command from the stream
	n, err := stream.Read(buff)
	if err != nil {
		log.Printf("[server] Error Reading Raw Data: %s", err)
		return err
	}

	// Handle handshake messages
	HandMess, err := pdu.HandMessageFromBytes(buff[:n])
	if err != nil {
		log.Printf("[server] Error decoding handshake header: %s", err)
		return err
	}

	log.Printf("[server] Handshake message received: %d", HandMess.Header.Type)

	if HandMess.Header.Type == pdu.HANDSHAKE_INIT {
		user, sessionToken, err := s.handleHandshake(stream, *HandMess)
		if err != nil {
			log.Printf("[server] Error handling handshake: %s", err)
			return err
		} else {
			return s.handleAuthenticatedUser(stream, user, sessionToken)
		}
	} else {
		s.sendError(stream, HandMess.Header, pdu.ACCESS_DENIED, "No handshake message sent, cannot establish connection")
		return errors.New("no handshake message sent, cannot establish connection")
	}
}

// handle the authentication of a user via a handshake message
func (s *Server) handleHandshake(stream quic.Stream, handshakeMessage pdu.HandMessage) (*User, []byte, error) {

	if handshakeMessage.AuthType == pdu.USER_PASSWORD {
		credentials := strings.SplitN(string(handshakeMessage.Data), ":", 2)
		if len(credentials) != 2 {
			return nil, nil, fmt.Errorf("invalid credentials format")
		}
		username, password := credentials[0], credentials[1]
		log.Printf("[server] Authenticating for user %s using password %s", username, password)

		user, authenticated := authenticateUser(username, password)
		if !authenticated {
			log.Printf("[server] Authentication failed for user %s", username)
			s.sendError(stream, handshakeMessage.Header, pdu.ACCESS_DENIED, "Authentication failed")
			return nil, nil, errors.New("authentication failed")
		}

		sessionToken := createSession(user)
		log.Printf("[server] User %s authenticated", username)

		transId := handshakeMessage.Header.TransactionID
		seqNum := handshakeMessage.Header.SeqNumber + uint32(1)
		handshakeMsg := pdu.NewHandMessage(pdu.HANDSHAKE_RESPONSE, transId, seqNum, pdu.USER_PASSWORD, sessionToken)
		handshakeBytes, err := pdu.HandMessageToBytes(handshakeMsg)
		if err != nil {
			log.Printf("[server] error creating handshake response bytes: %s", err)
			return nil, nil, errors.New("error creating handshake response")
		}

		_, err = stream.Write(handshakeBytes)
		if err != nil {
			log.Printf("[server] error writing handshake response to stream: %s", err)
			return nil, nil, errors.New("error writing handshake response")
		}

		log.Printf("[server] sending handshake response message")

		return user, sessionToken, nil
	}

	return nil, nil, fmt.Errorf("unsupported authentication type")
}

// handle the authenticated user and wait for the client to send a control or data message
func (s *Server) handleAuthenticatedUser(stream quic.Stream, user *User, token []byte) error {

	for {
		// Read the command from the stream
		buff := pdu.MakePduBuffer()
		n, err := stream.Read(buff)
		if err != nil && err != io.EOF {
			if strings.Contains(err.Error(), "timeout: no recent network activitity") {
				log.Printf("[server] stream closed due to network inactivity: %s", err.Error())
				return nil
			}
			log.Printf("[server] Error Reading Raw Data: %s", err.Error())
			return err
		} else if err == io.EOF || n == 0 {
			log.Printf("[server] waiting for next command from client")
			continue
		}

		// Remove any padding bytes
		data := pdu.RemovePadding(buff[:n])
		// Get mesasage
		msg, err := pdu.GetMessage(data)
		if err != nil {
			log.Printf("[server] error parsing messages: %s", err)
			return err
		}

		headtype, err := pdu.ExtractMessageType(msg)
		if err != nil {
			log.Printf("[server] error extracting message type: %s", err)
			return err
		}

		switch headtype {
		case pdu.DATA:
			handError := s.handleData(stream, msg, user)
			if handError != nil {
				log.Printf("[server] error handling message: %s", handError)
				return err
			}
		case pdu.CONTROL:
			state, handError := s.handleControl(stream, msg, token, user)
			if handError != nil {
				log.Printf("[server] error handling message: %s", handError)
				return err
			}
			if state == pdu.RESET {
				log.Printf("[server] connection reset")
				return nil
			}
		case pdu.ERROR:
			handError := s.handleError(stream, msg)
			if handError != nil {
				log.Printf("[server] error handling error message: %s", handError)
				return handError
			}
		case pdu.ACK:
			_, handError := s.handleAck(msg)
			if handError != nil {
				log.Printf("[server] error handling message: %s", handError)
				return err
			}
		default:
			log.Printf("[server] Unknown PDU type: %d", headtype)
			return fmt.Errorf("unknown PDU type: %d", headtype)
		}

	}
}

// function to handle any data being sent to the server
func (s *Server) handleData(stream quic.Stream, msg json.RawMessage, user *User) error {
	dataMessage, err := pdu.DataMessageFromBytes(msg)
	if err != nil {
		log.Printf("[server] Error decoding DataMessage: %s", err)
		return err
	}

	filename := dataMessage.Filename

	switch dataMessage.RequestedOp {
	case pdu.WRITE:

		if authorizeUser(user, "upload") {
			return s.handleUpload(stream, filename, dataMessage)
		} else {
			return s.sendError(stream, dataMessage.Header, pdu.ACCESS_DENIED, "User does not have permission to upload files")
		}
	case pdu.READ:
		//should only be initiated by the server after control message received
		return nil
	default:
		log.Printf("[server] Unknown Requested Operation: %d", dataMessage.RequestedOp)
		return fmt.Errorf("unknown Requested Operation: %d", dataMessage.RequestedOp)
	}

}

// handle the actual uploading of data. if more than one message is required a buffer will be kept
// until all data is received
func (s *Server) handleUpload(stream quic.Stream, filepath []byte, Mess *pdu.DataMessage) error {

	transactionID := Mess.Header.TransactionID
	filename := string(filepath)
	filepath = []byte(repository + filename)

	upload, ok := uploads[transactionID]
	if !ok {
		upload = &FileUpload{
			Filename:   Mess.Filename,
			Buffer:     make([]byte, 0, Mess.Header.Length),
			LastSeqNum: Mess.Header.SeqNumber,
		}
		uploads[transactionID] = upload
		log.Printf("[server] Data message received for file: %s", filename)
	}

	file, err := os.Create(string(filepath))
	if err != nil {
		log.Printf("[server] Error Creating File: %s", err)
		s.sendError(stream, Mess.Header, pdu.WRITE_ERROR, "Error creating file on server")
		return err
	}
	defer file.Close()

	if Mess.Header.Length < pdu.MAX_PDU_SIZE && Mess.Header.SeqNumber == 1 {
		_, err = file.Write(Mess.Data)
		if err != nil {
			log.Printf("[server] Error Writing to File: %s", err)
			s.sendError(stream, Mess.Header, pdu.WRITE_ERROR, "Error writing file to server")
			return err
		}
		delete(uploads, Mess.Header.TransactionID)

		log.Printf("[server] File %s uploaded successfully to %s", filename, repository)
		err := s.sendAck(stream, Mess.Header, pdu.COMPLETE, pdu.ACK_SUCCESS)
		if err != nil {
			log.Printf("[server] Error sending completion ack: %s", err)
			return err
		}

	} else if Mess.Header.Length < pdu.MAX_PDU_SIZE && Mess.Header.SeqNumber > 1 {
		_, err = file.Write(upload.Buffer)
		if err != nil {
			log.Printf("[server] Error Writing to File: %s", err)
			s.sendError(stream, Mess.Header, pdu.WRITE_ERROR, "Error writing file to server")
			return err
		}
		delete(uploads, Mess.Header.TransactionID)
		log.Printf("[server] File %s uploaded successfully to %s", filename, repository)
		err := s.sendAck(stream, Mess.Header, pdu.COMPLETE, pdu.ACK_SUCCESS)
		if err != nil {
			log.Printf("[server] Error sending completion ack: %s", err)
			return err
		}

	} else {
		if Mess.Header.SeqNumber > 1 && Mess.Header.SeqNumber != upload.LastSeqNum+1 {
			log.Printf("[server] Error: Received out of order data message")
			s.sendError(stream, Mess.Header, pdu.WRITE_ERROR, "Received out of order data message")
			return fmt.Errorf("received out of order data message")
		}
		upload.Buffer = append(upload.Buffer, Mess.Data...)
		upload.LastSeqNum = Mess.Header.SeqNumber
		return nil
	}

	return nil
}

// handles any request to download a file from the server
func (s *Server) handleDownload(stream quic.Stream, conMessage *pdu.ControlMessage, token []byte) error {

	filepath := conMessage.Data

	_, err := os.Stat(repository + string(filepath))
	if errors.Is(err, os.ErrNotExist) {
		s.sendError(stream, conMessage.Header, pdu.FILE_NOT_FOUND, "File not found on server")
		return err
	}

	file, err := os.Open(repository + string(filepath))
	if err != nil {
		log.Printf("[server] Error Opening File: %s", err)
		s.sendError(stream, conMessage.Header, pdu.READ_ERROR, "File could not be read")
		return err
	}
	defer file.Close()

	transaction_id := conMessage.Header.TransactionID
	seq_number := conMessage.Header.SeqNumber
	i := uint32(1)
	overhead := pdu.CalculateDataOverhead(token, filepath)
	data_buffer := pdu.MakeDataBuffer(overhead)
	for {
		n, err := file.Read(data_buffer)
		if err != nil && err != io.EOF {
			s.sendError(stream, conMessage.Header, pdu.READ_ERROR, "File could not be read")
			return fmt.Errorf("failed to read bytes from file buffer: %w", err)
		}

		if n == 0 {
			break
		}

		dataHeader := pdu.MessHeader{
			Type:          pdu.DATA,
			TransactionID: transaction_id,
			SeqNumber:     seq_number + i,
			Length:        overhead + uint32(n),
			Token:         token,
		}

		dataMsg := pdu.NewDataMessage(dataHeader, pdu.WRITE, filepath, data_buffer)
		dataBytes, err := pdu.DataMessageToBytes(dataMsg)
		if err != nil {
			s.sendError(stream, conMessage.Header, pdu.READ_ERROR, "failed to create bytes from DataMessage")
			return fmt.Errorf("failed to create bytes from DataMessage: %w", err)
		}

		// Pad the dataBytes to pdu.MAX_PDU_SIZE if necessary
		if len(dataBytes) < int(pdu.MAX_PDU_SIZE) {
			padding := make([]byte, pdu.MAX_PDU_SIZE-uint32(len(dataBytes)))
			dataBytes = append(dataBytes, padding...)
		}

		_, err = stream.Write(dataBytes)
		if err != nil {
			s.sendError(stream, conMessage.Header, pdu.READ_ERROR, "failed to send DataMessage")
			return fmt.Errorf("failed to send DataMessage: %w", err)
		}

		i++
	}
	err = s.sendAck(stream, conMessage.Header, pdu.COMPLETE, pdu.ACK_SUCCESS)
	if err != nil {
		s.sendError(stream, conMessage.Header, pdu.CONNECTION_INTERRUPTED, "failed to send DataMessage")
		log.Printf("[server] error sending ack for successful download: %s", err)
		return err
	}
	log.Printf("[server] File %s downloaded successfully. Waiting for client to send ack response...", filepath)
	return nil
}

// handles any control messages sent to the server
func (s *Server) handleControl(stream quic.Stream, raw []byte, token []byte, user *User) (uint8, error) {
	controlMessage, err := pdu.ControlMessageFromBytes(raw)
	if err != nil {
		log.Printf("[server] Error decoding ControlMessage: %s", err)
		return pdu.RESET, err
	}

	log.Printf("[server] Control action requested: %s", pdu.GetControlAsString(controlMessage.ControlCode))
	switch controlMessage.ControlCode {
	case pdu.START:
		err = s.sendAck(stream, controlMessage.Header, pdu.INITIATING, pdu.ACK_SUCCESS)
		if err != nil {
			log.Printf("[server] error sending ack for start control message: %s", err)
			return pdu.RESET, err
		}
		return pdu.INITIATING, nil
	case pdu.START_UPLOAD:
		if authorizeUser(user, "upload") {
			err = s.sendAck(stream, controlMessage.Header, pdu.UPLOADING, pdu.ACK_SUCCESS)
			if err != nil {
				log.Printf("[server] error sending ack for start upload control message: %s", err)
				return pdu.RESET, err
			}
			return pdu.UPLOADING, nil
		} else {
			log.Printf("[server] User not authorized to upload. Sending error message...")
			err = s.sendAck(stream, controlMessage.Header, pdu.IDLE, pdu.ACK_FAILURE)
			if err != nil {
				log.Printf("[server] error sending ack message for start upload control message: %s", err)
				return pdu.RESET, err
			}

			err = s.sendError(stream, controlMessage.Header, pdu.ACCESS_DENIED, "User not authorized to upload")
			if err != nil {
				log.Printf("[server] error sending error message for start upload control message: %s", err)
				return pdu.RESET, err
			}
			return pdu.IDLE, nil
		}
	case pdu.START_DOWNLOAD:
		if authorizeUser(user, "download") {
			err = s.sendAck(stream, controlMessage.Header, pdu.DOWNLOADING, pdu.ACK_SUCCESS)
			if err != nil {
				log.Printf("[server] error sending ack for start download control message: %s", err)
				return pdu.RESET, err
			}

			err = s.handleDownload(stream, controlMessage, token)
			if err != nil {
				log.Printf("[server] error handling download: %s", err)
				return pdu.RESET, err
			} else {
				var count int = 0
				for {

					buffer := pdu.MakePduBuffer()
					n, err := stream.Read(buffer)
					if err != nil && err != io.EOF {
						log.Printf("[server] error reading Ack bytes: %s", err)
						return pdu.RESET, err
					} else if err == io.EOF {
						if count < 5 {
							time.Sleep(1000 * time.Millisecond)
							count += 1
							continue
						} else {
							log.Printf("[server] no Ack response received after 5 seconds")
							return pdu.RESET, fmt.Errorf("[server] no Ack response received after 5 seconds")
						}
					}

					// Remove any padding bytes
					data := pdu.RemovePadding(buffer[:n])
					status, err := s.handleAck(data)
					if err != nil {
						log.Printf("[server] error converting bytes to Ack message: %s", err)
						return pdu.RESET, err
					}

					if status != pdu.ACK_SUCCESS {
						if status == pdu.ACK_RESEND_REQUESTED {
							err = s.handleDownload(stream, controlMessage, token)
							if err != nil {
								filename := string(controlMessage.Data)
								log.Printf("[server] error uploading file (retry unsuccessful): %s", filename)
								return pdu.RESET, err
							}
						} else {
							log.Printf("[server] error with transfer Ack Status: %d", status)
							return pdu.RESET, fmt.Errorf("[server] error with transfer Ack Status: %d", status)
						}
					} else {
						log.Printf("[server] received Ack signaling transfer success")
						break
					}
				}

				return pdu.COMPLETE, nil
			}
		} else {
			err = s.sendError(stream, controlMessage.Header, pdu.ACCESS_DENIED, "User does not have permission to download files")
			if err != nil {
				log.Printf("[server] error sending error for start download control message: %s", err)
				return pdu.RESET, err
			}
			return pdu.RESET, nil
		}

	case pdu.CLOSE_CONNECTION:
		deleteSession(token)
		return pdu.RESET, nil
	default:
		log.Printf("[server] Unknown Control Code: %d", controlMessage.ControlCode)
		s.sendError(stream, controlMessage.Header, pdu.INVALID_CONTROL_CODE, "Unknown Control Code")
		return pdu.RESET, errors.New("unknown Control Code")
	}

}

// handles any error messages sent to the server
func (s *Server) handleError(stream quic.Stream, raw []byte) error {
	errorMessage, err := pdu.ErrorMessageFromBytes(raw)
	if err != nil {
		log.Printf("[server] Error decoding ErrorMessage: %s", err)
		return err
	}

	err = s.sendAck(stream, errorMessage.Header, pdu.IDLE, pdu.ACK_SUCCESS)
	if err != nil {
		log.Printf("[server] error sending ack for error message: %s", err)
		return err
	}

	log.Printf("[server] Error received: %s", errorMessage.ErrorMessage)
	return nil
}

// handles any ack messages sent to the server
func (s *Server) handleAck(raw []byte) (uint8, error) {
	ackMessage, err := pdu.AckMessageFromBytes(raw)
	if err != nil {
		log.Printf("[server] Error decoding AckMessage: %s", err)
		return pdu.ACK_FAILURE, err
	}

	log.Printf("[server] ACK received for sequence number: %d", ackMessage.AcknowledgedSequenceNumber)
	return pdu.ACK_SUCCESS, nil
}

// handles any ack messages sent by the server
func (s *Server) sendAck(stream quic.Stream, header interface{}, state uint8, status uint8) error {

	switch h := header.(type) {
	case pdu.HandMessHeader:
		transId := h.TransactionID
		seqNumber := h.SeqNumber

		data := []byte("Handshake initialization message received.")
		ackHeader := pdu.HandMessHeader{
			Type:          pdu.ACK,
			Version:       pdu.Version,
			TransactionID: transId,
			SeqNumber:     seqNumber,
			Length:        pdu.HandHeadSize + pdu.HandMessSize + uint32(len(data)), // Adjust as necessary
			Flags:         pdu.NO_FLAG,
		}

		ackMessage, err := pdu.NewAckMessage(ackHeader, uint64(time.Now().Unix()), seqNumber, state, status, data)
		if err != nil {
			log.Printf("[server] Error creating AckMessage: %s", err)
			return err
		}

		ackBytes, err := pdu.AckMessageToBytes(ackMessage)
		if err != nil {
			log.Printf("[server] Error encoding AckMessage: %s", err)
			return err
		}

		_, err = stream.Write(ackBytes)
		if err != nil {
			log.Printf("[server] Error sending handshake acknowledgement: %s", err)
			return err
		}
		return nil
	case pdu.MessHeader:
		transId := h.TransactionID
		seqNumber := h.SeqNumber
		data := []byte("No data provided in acknowledgement message.")
		ackHeader := pdu.MessHeader{
			Type:          pdu.ACK,
			TransactionID: transId,
			SeqNumber:     seqNumber,
			Length:        pdu.HeaderSize + pdu.AckSize, // Adjust as necessary
			Token:         h.Token,
		}

		ackMessage, err := pdu.NewAckMessage(ackHeader, uint64(time.Now().Unix()), seqNumber, state, status, data)
		if err != nil {
			log.Printf("[server] Error creating AckMessage: %s", err)
			return err
		}

		log.Printf("[server] Sending acknowledgement message")

		ackBytes, err := pdu.AckMessageToBytes(ackMessage)
		if err != nil {
			log.Printf("[server] Error encoding AckMessage: %s", err)
			return err
		}

		// Pad the ackBytes to pdu.MAX_PDU_SIZE if necessary
		if len(ackBytes) < int(pdu.MAX_PDU_SIZE) {
			padding := make([]byte, pdu.MAX_PDU_SIZE-uint32(len(ackBytes)))
			ackBytes = append(ackBytes, padding...)
		}

		_, err = stream.Write(ackBytes)
		if err != nil {
			log.Printf("[server] Error sending AckMessage: %s", err)
			return err
		}
		return nil
	default:
		log.Printf("[server] Invalid header type in Ackmessage: %d", h)
		return errors.New("invalid header type in Ackmessage")
	}
}

// handles any error messages the server needs to send
func (s *Server) sendError(stream quic.Stream, header interface{}, errorCode uint8, errorMessage string) error {

	switch h := header.(type) {
	case pdu.HandMessHeader:
		errorHeader := pdu.MessHeader{
			Type:          pdu.ERROR,
			TransactionID: h.TransactionID,
			SeqNumber:     h.SeqNumber,
			Length:        pdu.HeaderSize + pdu.ErrSize + uint32(len(errorMessage)), // Adjust if change in error message
		}
		errorMsg := pdu.NewErrorMessage(errorHeader, uint64(time.Now().Unix()), errorCode, errorMessage)
		errorBytes, err := pdu.ErrorMessageToBytes(errorMsg)
		if err != nil {
			log.Printf("[server] Error encoding ErrorMessage during handshake: %s", err)
			return err
		}

		_, err = stream.Write(errorBytes)
		if err != nil {
			log.Printf("[server] Error sending ErrorMessage during handshake: %s", err)
			return err
		}
		return nil
	case pdu.MessHeader:
		errorHeader := pdu.MessHeader{
			Type:          pdu.ERROR,
			TransactionID: h.TransactionID,
			SeqNumber:     h.SeqNumber,
			Length:        pdu.HeaderSize + pdu.ErrSize + uint32(len(errorMessage)), // Adjust if change in error message
		}
		errorMsg := pdu.NewErrorMessage(errorHeader, uint64(time.Now().Unix()), errorCode, errorMessage)
		errorBytes, err := pdu.ErrorMessageToBytes(errorMsg)
		if err != nil {
			log.Printf("[server] Error encoding ErrorMessage: %s", err)
			return err
		}

		// Pad the ackBytes to pdu.MAX_PDU_SIZE if necessary
		if len(errorBytes) < int(pdu.MAX_PDU_SIZE) {
			padding := make([]byte, pdu.MAX_PDU_SIZE-uint32(len(errorBytes)))
			errorBytes = append(errorBytes, padding...)
		}

		_, err = stream.Write(errorBytes)
		if err != nil {
			log.Printf("[server] Error sending ErrorMessage: %s", err)
			return err
		}
		return nil
	default:
		log.Printf("[server] Invalid header type: %d", h)
		return errors.New("invalid header type")
	}
}
