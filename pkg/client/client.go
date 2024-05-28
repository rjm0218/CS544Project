package client

import (
	"bufio"
	"context"
	"crypto/tls"
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
	token string
}

func NewClient(cfg ClientConfig) *Client {
	cli := &Client{
		cfg: cfg,
	}

	if cfg.CertFile != "" {
		log.Printf("[cli] using cert file: %s", cfg.CertFile)
		t, err := util.BuildTLSClientConfigWithCert(cfg.CertFile)
		if err != nil {
			log.Fatal("[cli] error building TLS client config:", err)
			return nil
		}
		cli.tls = t
	} else {
		cli.tls = util.BuildTLSClientConfig()
	}

	cli.ctx = context.TODO()
	return cli
}

func (c *Client) Run() error {
	serverAddr := fmt.Sprintf("%s:%d", c.cfg.ServerAddr, c.cfg.PortNumber)
	conn, err := quic.DialAddr(c.ctx, serverAddr, c.tls, nil)
	if err != nil {
		log.Printf("[cli] error dialing server %s", err)
		return err
	}
	c.conn = conn

	// Perform handshake
	transId, seqNum, err := c.handshake()
	if err != nil {
		log.Printf("[cli] handshake error: %s", err)
		return err
	}

	return c.protocolHandler(transId, seqNum)
}

func (c *Client) handshake() (uint32, uint32, error) {
	stream, err := c.conn.OpenStreamSync(c.ctx)
	if err != nil {
		log.Printf("[cli] error opening stream %s", err)
		return 1, 1, err
	}
	defer stream.Close()

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
	handshakeMsg := pdu.NewHandMessage(pdu.HANDSHAKE_INIT, transId, seqNum, pdu.USER_PASSWORD, authData)
	seqNum += 1

	handshakeBytes, err := pdu.HandMessageToBytes(handshakeMsg)
	if err != nil {
		log.Printf("[cli] error creating handshake bytes: %s", err)
		return transId, seqNum, nil
	}

	_, err = stream.Write(handshakeBytes)
	if err != nil {
		log.Printf("[cli] error writing handshake to stream: %s", err)
		return transId, seqNum, nil
	}

	buffer := pdu.MakePduBuffer()
	n, err := stream.Read(buffer)
	if err != nil {
		log.Printf("[cli] error reading handshake response: %s", err)
		return transId, seqNum, nil
	}

	sessionToken := strings.TrimSpace(string(buffer[:n]))
	c.token = sessionToken
	log.Printf("[cli] received session token: %s", sessionToken)

	return transId, seqNum, nil
}

func (c *Client) protocolHandler(transaction_id uint32, seq_number uint32) error {
	stream, err := c.conn.OpenStreamSync(c.ctx)
	if err != nil {
		log.Printf("[cli] error opening stream %s", err)
		return err
	}

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Enter command (upload/download/close): ")
		command, _ := reader.ReadString('\n')
		command = strings.TrimSpace(command)

		filePath := ""
		if command != "close" {
			fmt.Print("Enter filename: ")
			filePath, _ := reader.ReadString('\n')
			filePath = strings.TrimSpace(filePath)
		}

		switch command {
		case "upload":
			err := c.uploadFile(stream, filePath, transaction_id, seq_number)
			if err != nil {
				log.Printf("[client] error uploading file: %s", err)
				return err
			}
			transaction_id += 1
		case "download":
			err := c.downloadFile(stream, filePath, transaction_id, seq_number)
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

func (c *Client) uploadFile(stream quic.Stream, filePath string, transaction_id uint32, seq_number uint32) error {

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	controlHeader := pdu.MessHeader{
		Type:          pdu.ERROR,
		TransactionID: transaction_id,
		SeqNumber:     seq_number,
		Length:        pdu.HeaderSize + pdu.ConSize,
	}

	controlMsg := pdu.NewControlMessage(controlHeader, uint64(time.Now().UnixNano()), pdu.START_UPLOAD)
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

	response, err := pdu.PduFromBytes(buffer[:n])
	if err != nil {
		return fmt.Errorf("failed to unmarshal server response: %w", err)
	}

	if response.Mtype != (pdu.TYPE_DATA | pdu.TYPE_ACK) {
		return fmt.Errorf("server did not acknowledge upload request")
	}

	_, err = io.Copy(stream, file)
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}

	return nil
}

func (c *Client) downloadFile(stream quic.Stream, filePath string) error {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter file path to download: ")
	filePath, _ := reader.ReadString('\n')
	filePath = strings.TrimSpace(filePath)

	stream, err := c.conn.OpenStreamSync(c.ctx)
	if err != nil {
		log.Printf("[client] error opening stream %s", err)
		return err
	}
	defer stream.Close()

	controlMsg := pdu.NewControlMessage(pdu.CONTROL, c.token, pdu.START_DOWNLOAD)
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

	response, err := pdu.PduFromBytes(buffer[:n])
	if err != nil {
		return fmt.Errorf("failed to unmarshal server response: %w", err)
	}

	if response.Mtype != (pdu.TYPE_DATA | pdu.TYPE_ACK) {
		return fmt.Errorf("server did not acknowledge download request")
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	_, err = io.Copy(file, stream)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}

	return nil
}

func (c *Client) closeConnection(stream quic.Stream) error {
	stream, err := c.conn.OpenStreamSync(c.ctx)
	if err != nil {
		log.Printf("[client] error opening stream %s", err)
		return err
	}
	defer stream.Close()

	controlMsg := pdu.NewControlMessage(pdu.CONTROL, c.token, pdu.CLOSE_CONNECTION)
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
