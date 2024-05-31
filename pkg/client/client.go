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
		log.Printf("[client] error dialing server %s", err)
		return err
	}
	c.conn = conn

	// Perform handshake
	stream, err := c.handshake()
	if err != nil {
		log.Printf("[client] handshake error: %s", err)
		if err.Error() == "authentication failed" {
			for {
				stream, err = c.handshake()
				if err != nil {
					log.Printf("[client] handshake error: %s", err)
					continue
				} else {
					break
				}
			}
		} else {
			return err
		}
	}

	return c.protocolHandler(stream)
}

// initiate the handshake with server
func (c *Client) handshake() (quic.Stream, error) {
	stream, err := c.conn.OpenStreamSync(c.ctx)
	if err != nil {
		log.Printf("[client] error opening stream %s", err)
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
		log.Printf("[client] error creating handshake bytes: %s", err)
		return stream, err
	}
	_, err = stream.Write(handshakeBytes)
	if err != nil {
		log.Printf("[client] error writing handshake to stream: %s", err)
		return stream, err
	}

	buffer := pdu.MakePduBuffer()
	n, err := stream.Read(buffer)
	if err != nil {
		log.Printf("[client] error reading handshake response bytes: %s", err)
		return stream, err
	}

	//remove any padding
	data := pdu.RemovePadding(buffer[:n])
	msg, err := pdu.GetMessage(data)
	if err != nil {
		log.Printf("[client] error parsing response bytes: %s", err)
		return stream, err
	}

	headtype, err := pdu.ExtractMessageType(msg)
	if err != nil {
		log.Printf("[client] error extracting message type from response bytes: %s", err)
		return stream, err
	}

	if headtype != pdu.HANDSHAKE_RESPONSE {
		if headtype == pdu.ERROR {
			errMess, err := pdu.ErrorMessageFromBytes(msg)
			if err != nil {
				log.Printf("[client] error converting bytes to error message: %s", err)
				return stream, err
			}
			log.Printf("[client] error: %s", errMess.ErrorMessage)
			return stream, errors.New(errMess.ErrorMessage)
		}
		log.Printf("[client] error: expected handshake response, got %s", pdu.GetTypeAsString(headtype))
		return stream, errors.New("error: expected handshake response, got " + pdu.GetTypeAsString(headtype))
	}

	responseMess, err := pdu.HandMessageFromBytes(buffer[:n])
	if err != nil {
		log.Printf("[client] error converting bytes to handshake response: %s", err)
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
				log.Printf("[client] error uploading file: %s", err.Error())
				continue
			}
			transaction_id += 1

			for {
				buffer := pdu.MakePduBuffer()
				n, err := stream.Read(buffer)
				if err != nil && err != io.EOF {
					log.Printf("[client] error reading Ack bytes: %s", err)
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
							log.Printf("[client] error uploading file (retry): %s", filename)
							break
						}
					} else {
						log.Printf("[client] error with transfer Ack Status: %d", status)
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
				log.Printf("[client] error downloading file: %s", err)
				return err
			}
			transaction_id += 1
		case "close":
			err := c.closeConnection(stream, transaction_id, seq_number)
			if err != nil {
				log.Printf("[client] error closing connection: %s", err)
				return err
			}
			return nil
		default:
			fmt.Println("Invalid command. Please enter upload, download, or close.")
		}

	}
}

// handle the uploading of a file to the server
func (c *Client) uploadFile(stream quic.Stream, filePath string, transaction_id uint32, seq_number uint32) error {

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	fileName := []byte(strings.Split(filePath, "/")[len(strings.Split(filePath, "/"))-1])

	controlHeader := pdu.MessHeader{
		Type:          pdu.CONTROL,
		TransactionID: transaction_id,
		SeqNumber:     seq_number,
		Length:        pdu.HeaderSize + pdu.ConSize,
		Token:         c.token,
	}

	seq_number += 1
	controlMsg := pdu.NewControlMessage(controlHeader, uint64(time.Now().UnixNano()), pdu.START_UPLOAD, []byte(fileName))
	controlBytes, err := pdu.ControlMessageToBytes(controlMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal control message: %w", err)
	}

	_, err = stream.Write(controlBytes)
	if err != nil {
		return fmt.Errorf("failed to send control message: %w", err)
	}

	buffer := pdu.MakePduBuffer()
	n, err := stream.Read(buffer)
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read bytes from file buffer: %w", err)
	}

	// Remove any padding bytes
	data := pdu.RemovePadding(buffer[:n])
	status, err := c.handleAck(data)
	if err != nil {
		return err
	}

	if status != pdu.ACK_SUCCESS {
		buffer := pdu.MakePduBuffer()
		n, err := stream.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read bytes from file buffer: %w", err)
		}

		// Remove any padding bytes
		data := pdu.RemovePadding(buffer[:n])
		errMess, err := pdu.ErrorMessageFromBytes(data)
		if err != nil {
			return fmt.Errorf("failed to unmarshal error message: %w", err)
		}
		return errors.New(errMess.ErrorMessage)
	} else {
		log.Printf("[client] received AckMessage that server is ready for upload")
	}

	overhead := pdu.CalculateDataOverhead(c.token, fileName)

	data_buffer := pdu.MakeDataBuffer(overhead)

	for {
		n, err := file.Read(data_buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read bytes from file buffer: %w", err)
		}

		if n == 0 {
			break
		}

		dataHeader := pdu.MessHeader{
			Type:          pdu.DATA,
			TransactionID: transaction_id,
			SeqNumber:     seq_number,
			Length:        overhead + uint32(n),
			Token:         c.token,
		}

		seq_number += 1

		dataMsg := pdu.NewDataMessage(dataHeader, pdu.WRITE, fileName, data_buffer[:n])
		dataBytes, err := pdu.DataMessageToBytes(dataMsg)
		if err != nil {
			return fmt.Errorf("failed to create bytes from DataMessage: %w", err)
		}

		//Pad the dataBytes to pdu.MAX_PDU_SIZE if necessary
		if len(dataBytes) < int(pdu.MAX_PDU_SIZE) {
			padding := make([]byte, pdu.MAX_PDU_SIZE-uint32(len(dataBytes)))
			dataBytes = append(dataBytes, padding...)
		}

		_, err = stream.Write(dataBytes)
		if err != nil {
			return fmt.Errorf("failed to send DataMessage: %w", err)
		}
	}

	log.Printf("[client] finished sending file. Waiting for server to send ack...")
	return nil
}

// handle the downloading of a file from the server
func (c *Client) downloadFile(stream quic.Stream, filePath string, transaction_id uint32, seq_number uint32) error {

	controlHeader := pdu.MessHeader{
		Type:          pdu.CONTROL,
		TransactionID: transaction_id,
		SeqNumber:     seq_number,
		Length:        pdu.HeaderSize + pdu.ConSize,
		Token:         c.token,
	}

	controlMsg := pdu.NewControlMessage(controlHeader, uint64(time.Now().UnixNano()), pdu.START_DOWNLOAD, []byte(filePath))
	controlBytes, err := pdu.ControlMessageToBytes(controlMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal control message: %w", err)
	}

	_, err = stream.Write(controlBytes)
	if err != nil {
		return fmt.Errorf("failed to send control message: %w", err)
	}

	buffer := pdu.MakePduBuffer()
	n, err := stream.Read(buffer)
	if err != nil {
		return fmt.Errorf("failed to read server response: %w", err)
	}

	data := pdu.RemovePadding(buffer[:n])
	status, err := c.handleAck(data)
	if err != nil {
		return err
	}

	if status != pdu.ACK_SUCCESS {
		return fmt.Errorf("server did not acknowledge download request")
	} else {
		log.Printf("[client] received Ack signaling download in progress")
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()
	data_buffer := pdu.MakePduBuffer()
	for {

		n, err := stream.Read(data_buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read bytes from file buffer: %w", err)
		} else if err == io.EOF && n == 0 {
			break
		}

		// Remove any padding bytes
		data := pdu.RemovePadding(data_buffer[:n])
		// Get mesasage
		msg, err := pdu.GetMessage(data)
		if err != nil {
			return fmt.Errorf("failed to get message from bytes: %w", err)
		}

		headtype, err := pdu.ExtractMessageType(msg)

		if err != nil {
			return fmt.Errorf("failed to extract message type: %w", err)
		} else if headtype == pdu.ERROR {
			errMess, err := pdu.ErrorMessageFromBytes(msg)
			if err != nil {
				return fmt.Errorf("failed to unmarshal ErrorMessage: %w", err)
			} else if errMess.ErrorCode == pdu.FILE_NOT_FOUND {
				log.Printf("[client] %s", errMess.ErrorMessage)
				return nil
			} else if errMess.ErrorCode == pdu.READ_ERROR {
				log.Printf("[client] %s", errMess.ErrorMessage)
				return fmt.Errorf("[client] %s", errMess.ErrorMessage)
			}
			return fmt.Errorf("server sent error message")
		} else if headtype == pdu.ACK {
			status, err := c.handleAck(msg)
			if err != nil {
				return err
			} else if status == pdu.ACK_SUCCESS {
				break
			}
		} else if headtype != pdu.DATA {
			return fmt.Errorf("server sent message of type %s, expected DATA", pdu.GetTypeAsString(headtype))
		}

		dataMess, err := pdu.DataMessageFromBytes(msg)
		if err != nil {
			return fmt.Errorf("failed to create DataMessage from bytes: %w", err)
		}

		_, err = file.Write(dataMess.Data)
		if err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
	}

	err = c.sendAck(stream, controlHeader, pdu.COMPLETE, pdu.ACK_SUCCESS)

	if err != nil {
		return fmt.Errorf("failed to send AckMessage: %w", err)
	} else {
		log.Printf("[client] sent Ack signaling download success")
		return nil
	}

}

// handles any ack messages sent to the server
func (c *Client) handleAck(raw []byte) (uint8, error) {
	ackMessage, err := pdu.AckMessageFromBytes(raw)
	if err != nil {
		log.Printf("[client] Error decoding AckMessage: %s", err)
		return pdu.ACK_FAILURE, err
	}

	log.Printf("[client] ACK received for sequence number: %d", ackMessage.AcknowledgedSequenceNumber)
	return pdu.ACK_SUCCESS, nil
}

// handles sending any ack messages back to server
func (c *Client) sendAck(stream quic.Stream, header interface{}, state uint8, status uint8) error {

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
			log.Printf("[client] Error creating AckMessage: %s", err)
			return err
		}

		ackBytes, err := pdu.AckMessageToBytes(ackMessage)
		if err != nil {
			log.Printf("[client] Error encoding AckMessage: %s", err)
			return err
		}
		_, err = stream.Write(ackBytes)
		if err != nil {
			log.Printf("[client] Error sending handshake acknowledgement: %s", err)
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
			log.Printf("[client] Error creating AckMessage: %s", err)
			return err
		}

		log.Printf("[client] Sending acknowledgement message")

		ackBytes, err := pdu.AckMessageToBytes(ackMessage)
		if err != nil {
			log.Printf("[client] Error encoding AckMessage: %s", err)
			return err
		}

		// Pad the ackBytes to pdu.MAX_PDU_SIZE if necessary
		if len(ackBytes) < int(pdu.MAX_PDU_SIZE) {
			padding := make([]byte, pdu.MAX_PDU_SIZE-uint32(len(ackBytes)))
			ackBytes = append(ackBytes, padding...)
		}

		_, err = stream.Write(ackBytes)
		if err != nil {
			log.Printf("[client] Error sending AckMessage: %s", err)
			return err
		}
		return nil
	default:
		log.Printf("[client] Invalid header type in Ackmessage: %d", h)
		return errors.New("invalid header type in Ackmessage")
	}
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
	return nil
}
