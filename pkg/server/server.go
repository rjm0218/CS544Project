package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"CS544PROJECT/pkg/errors"
	"CS544PROJECT/pkg/pdu"
	"CS544PROJECT/pkg/util"

	"github.com/quic-go/quic-go"
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
		errHand.LogError(err, "error listening")
		return err
	}

	//SERVER LOOP
	for {
		log.Println("Accepting new session")
		sess, err := listener.Accept(s.ctx)
		if err != nil {
			errHand.LogError(err, "error accepting new session")
			return err
		}

		go s.streamHandler(sess)
	}
}

// handle a session and wait for the client to initiate a stream
func (s *Server) streamHandler(sess quic.Connection) {
	for {
		log.Print("[server] waiting for client to open stream")
		stream, err := sess.AcceptStream(s.ctx)
		if err != nil {
			errHand.LogError(err, "stream closed")
			break
		}

		//Handle protocol activity on stream
		s.protocolHandler(stream)
	}
}

// handle the protocol activity on a stream including setting up handshake and data
func (s *Server) protocolHandler(stream quic.Stream) error {
	buff := pdu.MakePduBuffer()

	// Read the command from the stream
	n, err := stream.Read(buff)
	if err != nil {
		errHand.LogError(err, "error reading raw data from stream")
		return err
	}

	// Handle handshake messages
	HandMess, err := pdu.HandMessageFromBytes(buff[:n])
	if err != nil {
		errHand.LogError(err, "error getting handshake message from raw data")
		return err
	}

	log.Printf("[server] Handshake message received: %d", HandMess.Header.Type)

	if HandMess.Header.Type == pdu.HANDSHAKE_INIT {
		user, sessionToken, err := s.handleHandshake(stream, *HandMess)
		if err != nil {
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
			s.sendError(stream, handshakeMessage.Header, pdu.INVALID_CRED, "invalid credentials format")
			return nil, nil, errors.New("invalid credentials format")
		}
		username, password := credentials[0], credentials[1]
		log.Printf("[server] Authenticating for user %s using password %s", username, password)

		user, authenticated := authenticateUser(username, password)
		if !authenticated {
			log.Printf("[server] Authentication failed for user %s", username)
			s.sendError(stream, handshakeMessage.Header, pdu.INVALID_CRED, "authentication failed")
			return nil, nil, errors.New("authentication failed")
		}

		sessionToken := createSession(user)
		log.Printf("[server] User %s authenticated", username)

		transId := handshakeMessage.Header.TransactionID
		seqNum := handshakeMessage.Header.SeqNumber + uint32(1)
		handshakeMsg := pdu.NewHandMessage(pdu.HANDSHAKE_RESPONSE, transId, seqNum, pdu.USER_PASSWORD, sessionToken)
		handshakeBytes, err := pdu.HandMessageToBytes(handshakeMsg)
		if err != nil {
			errHand.LogError(err, "error creating handshake response bytes")
			return nil, nil, errors.New("error creating handshake response")
		}

		_, err = stream.Write(handshakeBytes)
		if err != nil {
			errHand.LogError(err, "error writing handshake response to stream")
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
			if strings.Contains(err.Error(), "timeout") {
				log.Printf("[server] stream closed due to network inactivity: %s", err.Error())
				return nil
			}
			errHand.LogError(err, "error reading raw data from stream")
			return err
		} else if err == io.EOF || n == 0 {
			log.Printf("[server] waiting for next command from client")
			continue
		}

		// Get raw mesasage
		msg, err := pdu.GetMessage(buff[:n])
		if err != nil {
			errHand.LogError(err, "error parsing message")
			return err
		}

		headtype, err := pdu.ExtractMessageType(msg)
		if err != nil {
			errHand.LogError(err, "error extracting message type")
			return err
		}

		switch headtype {
		case pdu.DATA:
			handError := s.handleData(stream, msg, user)
			if handError != nil {
				errHand.LogError(handError, "error handling Data message")
				return handError
			}
		case pdu.CONTROL:
			state, handError := s.handleControl(stream, msg, token, user)
			if handError != nil {
				errHand.LogError(handError, "error handling Control message")
				return handError
			}
			if state == pdu.RESET {
				log.Printf("[server] connection terminated for user: %s", user.Username)
				return nil
			}
		case pdu.ERROR:
			handError := s.handleError(stream, msg)
			if handError != nil {
				errHand.LogError(handError, "error handling Error message")
				return handError
			}
		case pdu.ACK:
			_, handError := s.handleAck(msg)
			if handError != nil {
				errHand.LogError(handError, "error handling Ack message")
				return handError
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
		errHand.LogError(err, "error decoding DataMessage")
		return err
	}

	if !validSessionToken(dataMessage.Header.Token) {
		log.Printf("[server] Invalid session token")
		s.sendError(stream, dataMessage.Header, pdu.ACCESS_DENIED, "Invalid session token")
		return errors.New("invalid session token")
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

// handles any control messages sent to the server
func (s *Server) handleControl(stream quic.Stream, raw []byte, token []byte, user *User) (uint8, error) {
	controlMessage, err := pdu.ControlMessageFromBytes(raw)
	if err != nil {
		errHand.LogError(err, "error decoding ControlMessage")
		return pdu.RESET, err
	}

	if !validSessionToken(controlMessage.Header.Token) {
		log.Printf("[server] Invalid session token")
		s.sendError(stream, controlMessage.Header, pdu.ACCESS_DENIED, "Invalid session token")
		return pdu.RESET, errors.New("invalid session token")
	}

	log.Printf("[server] Control action requested: %s", pdu.GetControlAsString(controlMessage.ControlCode))
	switch controlMessage.ControlCode {
	case pdu.START:
		err = s.sendAck(stream, controlMessage.Header, pdu.INITIATING, pdu.ACK_SUCCESS)
		if err != nil {
			errHand.LogError(err, "error sending Ack for start control message")
			return pdu.RESET, err
		}
		return pdu.INITIATING, nil
	case pdu.START_UPLOAD:
		if authorizeUser(user, "upload") {
			err = s.sendAck(stream, controlMessage.Header, pdu.UPLOADING, pdu.ACK_SUCCESS)
			if err != nil {
				errHand.LogError(err, "error sending Ack for start upload control message")
				return pdu.RESET, err
			}
			return pdu.UPLOADING, nil
		} else {
			log.Printf("[server] User not authorized to upload. Sending error message...")
			err = s.sendAck(stream, controlMessage.Header, pdu.IDLE, pdu.ACK_FAILURE)
			if err != nil {
				errHand.LogError(err, "error sending Ack for unauthorized upload control message")
				return pdu.RESET, err
			}

			err = s.sendError(stream, controlMessage.Header, pdu.ACCESS_DENIED, "User not authorized to upload")
			if err != nil {
				errHand.LogError(err, "error sending error message for upload control message")
				return pdu.RESET, err
			}
			return pdu.IDLE, nil
		}
	case pdu.START_DOWNLOAD:
		if authorizeUser(user, "download") {
			err = s.sendAck(stream, controlMessage.Header, pdu.DOWNLOADING, pdu.ACK_SUCCESS)
			if err != nil {
				errHand.LogError(err, "error sending Ack for download control message")
				return pdu.RESET, err
			}

			err = s.handleDownload(stream, controlMessage, token)
			if err != nil {
				errHand.LogError(err, "error handling download")
				return pdu.RESET, err
			} else {
				var count int = 0
				for {

					buffer := pdu.MakePduBuffer()
					n, err := stream.Read(buffer)
					if err != nil && err != io.EOF {
						errHand.LogError(err, "error reading expected Ack bytes")
						return pdu.RESET, err
					} else if err == io.EOF {
						if count < 5 {
							time.Sleep(1000 * time.Millisecond)
							count += 1
							continue
						} else {
							err = errors.New("no Ack response")
							errHand.LogError(err, "no Ack response received after 5 seconds")
							return pdu.RESET, fmt.Errorf("[server] no Ack response received after 5 seconds")
						}
					}

					// Remove any padding bytes
					msg, err := pdu.GetMessage(buffer[:n])
					if err != nil {
						errHand.LogError(err, "failed to extract message")
						return pdu.RESET, err
					}

					headtype, err := pdu.ExtractMessageType(msg)
					if err != nil {
						errHand.LogError(err, "error extracting message type from response message")
						return pdu.RESET, err
					}

					if headtype != pdu.ACK {
						err = errors.New("expected Ack message, got " + pdu.GetTypeAsString(headtype))
						errHand.LogError(err, "expected Ack message, got "+pdu.GetTypeAsString(headtype))
						return pdu.RESET, err
					}

					status, err := s.handleAck(msg)
					if err != nil {
						errHand.LogError(err, "error converting bytes to Ack message")
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

	var errorHeader pdu.MessHeader
	switch h := header.(type) {
	case pdu.HandMessHeader:
		errorHeader = pdu.MessHeader{
			Type:          pdu.ERROR,
			TransactionID: h.TransactionID,
			SeqNumber:     h.SeqNumber,
			Length:        pdu.HeaderSize + pdu.ErrSize + uint32(len(errorMessage)),
		}
	case pdu.MessHeader:
		errorHeader = pdu.MessHeader{
			Type:          pdu.ERROR,
			TransactionID: h.TransactionID,
			SeqNumber:     h.SeqNumber,
			Length:        pdu.HeaderSize + pdu.ErrSize + uint32(len(errorMessage)),
			Token:         h.Token,
		}
	default:
		log.Printf("[server] Invalid header type: %v", h)
		return fmt.Errorf("invalid header type: %v", h)
	}

	errorMsg := pdu.NewErrorMessage(errorHeader, uint64(time.Now().Unix()), errorCode, errorMessage)
	errorBytes, err := pdu.ErrorMessageToBytes(errorMsg)
	if err != nil {
		log.Printf("[server] Error encoding ErrorMessage: %s", err)
		return err
	}

	// Pad the errorBytes to pdu.MAX_PDU_SIZE if necessary
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
}
