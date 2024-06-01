package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"CS544PROJECT/pkg/errors"
	"CS544PROJECT/pkg/pdu"
	"CS544PROJECT/pkg/util"

	"github.com/quic-go/quic-go"
)

type ClientConfig struct {
	ServerAddr string
	PortNumber int
	CertFile   string
}

type Client struct {
	cfg   ClientConfig
	tls   *tls.Config
	conn  quic.Connection
	ctx   context.Context
	token []byte
}

// create a new client
func NewClient(cfg ClientConfig) *Client {
	cli := &Client{
		cfg: cfg,
	}

	if cfg.CertFile != "" {
		log.Printf("[client] using cert file: %s", cfg.CertFile)
		t, err := util.BuildTLSClientConfigWithCert(cfg.CertFile)
		if err != nil {
			log.Fatal("[client] error building TLS client config:", err)
			return nil
		}
		cli.tls = t
	} else {
		cli.tls = util.BuildTLSClientConfig()
	}

	cli.ctx = context.TODO()
	return cli
}

// run the instance of a client
func (c *Client) Run() error {
	serverAddr := fmt.Sprintf("%s:%d", c.cfg.ServerAddr, c.cfg.PortNumber)
	conn, err := quic.DialAddr(c.ctx, serverAddr, c.tls, nil)
	if err != nil {
		errHand.LogError(err, "error dialing server")
		return err
	}
	c.conn = conn

	// Perform handshake
	stream, err := c.handshake()
	if err != nil {
		if err.Error() == "authentication failed" {
			for {
				stream, err = c.handshake()
				if err != nil {
					continue
				} else {
					break
				}
			}
		} else {
			return err
		}
	}

	c.protocolHandler(stream)
	stream.Close()
	return nil
}

// initiate the handshake with server
func (c *Client) handshake() (quic.Stream, error) {
	stream, err := c.conn.OpenStreamSync(c.ctx)
	if err != nil {
		errHand.LogError(err, "error opening stream")
		return nil, err
	}

	// Prompt for username and password
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("Enter Password: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)
	authData := fmt.Sprintf("%s:%s", username, password)

	transId := pdu.StartTranId
	seqNum := pdu.StartSeqNum
	handshakeMsg := pdu.NewHandMessage(pdu.HANDSHAKE_INIT, transId, seqNum, pdu.USER_PASSWORD, []byte(authData))
	seqNum += 1

	handshakeBytes, err := pdu.HandMessageToBytes(handshakeMsg)
	if err != nil {
		errHand.LogError(err, "error creating handshake bytes")
		return stream, err
	}
	_, err = stream.Write(handshakeBytes)
	if err != nil {
		errHand.LogError(err, "error writing handshake to stream")
		return stream, err
	}

	buffer := pdu.MakePduBuffer()
	n, err := stream.Read(buffer)
	if err != nil {
		errHand.LogError(err, "error reading handshake response bytes from stream")
		return stream, err
	}

	//Get the raw message
	msg, err := pdu.GetMessage(buffer[:n])
	if err != nil {
		errHand.LogError(err, "error parsing response bytes from stream")
		return stream, err
	}

	headtype, err := pdu.ExtractMessageType(msg)
	if err != nil {
		errHand.LogError(err, "error extracting message type from response message")
		return stream, err
	}

	if headtype != pdu.HANDSHAKE_RESPONSE {
		if headtype == pdu.ERROR {
			errMess, err := pdu.ErrorMessageFromBytes(msg)
			if err != nil {
				errHand.LogError(err, "error converting raw message to error message")
				return stream, err
			}
			errHand.LogError(nil, "error during handshake:"+errMess.ErrorMessage)
			return stream, errors.New(errMess.ErrorMessage)
		}
		errHand.LogError(nil, "expected handshake response, got "+pdu.GetTypeAsString(headtype))
		return stream, errors.New("error: expected handshake response, got " + pdu.GetTypeAsString(headtype))
	}

	responseMess, err := pdu.HandMessageFromBytes(buffer[:n])
	if err != nil {
		errHand.LogError(err, "error converting bytes to handshake response")
		return stream, err
	}

	c.token = responseMess.Data
	log.Printf("[client] received session token: %s", responseMess.Data)

	return stream, nil
}

// handle any commands by the client
func (c *Client) protocolHandler(stream quic.Stream) error {

	reader := bufio.NewReader(os.Stdin)
	transaction_id := pdu.StartTranId
	seq_number := pdu.StartSeqNum

	for {
		fmt.Print("Enter command (upload/download/close): ")
		command, _ := reader.ReadString('\n')
		command = strings.TrimSpace(command)

		switch command {
		case "upload":
			fmt.Print("Enter filename: ")
			filePath, _ := reader.ReadString('\n')
			filename := strings.TrimSpace(filePath)
			err := c.uploadFile(stream, filename, transaction_id, seq_number)
			if err != nil {
				if strings.Contains(err.Error(), "timeout") {
					return err
				}
				errHand.LogError(err, "error uploading file")
				continue
			}
			transaction_id += 1

			for {
				buffer := pdu.MakePduBuffer()
				n, err := stream.Read(buffer)
				if err != nil && err != io.EOF {
					errHand.LogError(err, "error reading Ack bytes")
					break
				}

				data := pdu.RemovePadding(buffer[:n])
				status, err := c.handleAck(data)
				if err != nil {
					break
				}

				if status != pdu.ACK_SUCCESS {
					if status == pdu.ACK_RESEND_REQUESTED {
						err := c.uploadFile(stream, filename, transaction_id, seq_number)
						if err != nil {
							errHand.LogError(err, "error retrying upload for: "+filename)
							break
						}
					} else {
						errHand.LogError(nil, "transfer Ack message status was ACK_FAILURE")
						break
					}
				} else {
					log.Printf("[client] received Ack signaling transfer success")
					break
				}
			}

		case "download":
			fmt.Print("Enter filename: ")
			filePath, _ := reader.ReadString('\n')
			filename := strings.TrimSpace(filePath)
			err := c.downloadFile(stream, filename, transaction_id, seq_number)
			if err != nil {
				errHand.LogError(err, "error downloading file: "+filename)
				return err
			}
			transaction_id += 1
		case "close":
			err := c.closeConnection(stream, transaction_id, seq_number)
			if err != nil {
				errHand.LogError(err, "error closing connection")
				return err
			}
			return nil
		default:
			log.Printf("Invalid command. Please enter upload, download, or close.")
		}

	}
}

// handles any ack messages sent to the server
func (c *Client) handleAck(raw []byte) (uint8, error) {
	ackMessage, err := pdu.AckMessageFromBytes(raw)
	if err != nil {
		errHand.LogError(err, "error decoding AckMessage")
		return pdu.ACK_FAILURE, err
	}

	return ackMessage.Status, nil
}

// handles sending any ack messages back to server
func (c *Client) sendAck(stream quic.Stream, header interface{}, state uint8, status uint8) error {

	var ackHeader interface{}
	var data []byte
	var transaction_id uint32
	var seq_number uint32
	switch h := header.(type) {
	case pdu.HandMessHeader:
		transaction_id = h.TransactionID
		seq_number = h.SeqNumber
		data = []byte("Handshake initialization message received.")
		ackHeader = pdu.HandMessHeader{
			Type:          pdu.ACK,
			Version:       pdu.Version,
			TransactionID: transaction_id,
			SeqNumber:     seq_number,
			Length:        pdu.HandHeadSize + pdu.HandMessSize + uint32(len(data)),
			Flags:         pdu.NO_FLAG,
		}
	case pdu.MessHeader:
		transaction_id = h.TransactionID
		seq_number = h.SeqNumber
		data = []byte("") //no data in normal Ack message
		ackHeader = pdu.MessHeader{
			Type:          pdu.ACK,
			TransactionID: transaction_id,
			SeqNumber:     0,
			Length:        pdu.HeaderSize + pdu.AckSize,
			Token:         h.Token,
		}
	default:
		return fmt.Errorf("invalid header type: %v", h)
	}

	ackMessage, err := pdu.NewAckMessage(ackHeader, uint64(time.Now().Unix()), seq_number, state, status, data)
	if err != nil {
		return fmt.Errorf("error creating AckMessage: %w", err)
	}

	ackBytes, err := pdu.AckMessageToBytes(ackMessage)
	if err != nil {
		return fmt.Errorf("error encoding AckMessage: %w", err)
	}

	// Pad the ackBytes to MAX_PDU_SIZE if necessary
	if len(ackBytes) < int(pdu.MAX_PDU_SIZE) {
		padding := make([]byte, pdu.MAX_PDU_SIZE-uint32(len(ackBytes)))
		ackBytes = append(ackBytes, padding...)
	}

	_, err = stream.Write(ackBytes)
	if err != nil {
		return fmt.Errorf("error sending AckMessage: %w", err)
	}

	return nil
}

// handles the close command to terminate a connection with the server
func (c *Client) closeConnection(stream quic.Stream, transaction_id uint32, seq_number uint32) error {

	controlHeader := pdu.MessHeader{
		Type:          pdu.CONTROL,
		TransactionID: transaction_id,
		SeqNumber:     seq_number,
		Length:        pdu.HeaderSize + pdu.ConSize,
		Token:         c.token,
	}

	controlMsg := pdu.NewControlMessage(controlHeader, uint64(time.Now().UnixNano()), pdu.CLOSE_CONNECTION, []byte(""))
	controlBytes, err := pdu.ControlMessageToBytes(controlMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal control message: %w", err)
	}

	_, err = stream.Write(controlBytes)
	if err != nil {
		return fmt.Errorf("failed to send control message: %w", err)
	}

	log.Printf("[client] sent close connection command")

	// added sleep because running on Linux the control message wasn't making
	//it before the stream was closed
	time.Sleep(2000 * time.Millisecond)

	return nil
}
