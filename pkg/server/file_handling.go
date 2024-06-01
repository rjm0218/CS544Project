package server

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"CS544PROJECT/pkg/errors"
	"CS544PROJECT/pkg/pdu"

	"github.com/quic-go/quic-go"
)

const (
	REPO = "./repository/"
)

// structure to hold a file upload in progress
type FileUpload struct {
	Filename   []byte
	Buffer     []byte
	LastSeqNum uint32
	TotalBytes uint32
}

// structure to track all the file uploads in progress
var uploads = make(map[uint32]*FileUpload)

// handle the actual uploading of data. if more than one message is required a buffer will be kept
// until all data is received
func (s *Server) handleUpload(stream quic.Stream, filepath []byte, Mess *pdu.DataMessage) error {

	transactionID := Mess.Header.TransactionID
	filename := string(filepath)
	filepath = []byte(REPO + filename)

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
		errHand.LogError(err, "error creating file on server")
		s.sendError(stream, Mess.Header, pdu.WRITE_ERROR, "Error creating file on server")
		return err
	}
	defer file.Close()

	if Mess.Header.Length < pdu.MAX_PDU_SIZE && Mess.Header.SeqNumber == 1 {
		_, err = file.Write(Mess.Data)
		if err != nil {
			errHand.LogError(err, "error writing file to server")
			s.sendError(stream, Mess.Header, pdu.WRITE_ERROR, "Error writing file to server")
			return err
		}
		delete(uploads, Mess.Header.TransactionID)

		log.Printf("[server] File %s uploaded successfully to %s", filename, REPO)
		err := s.sendAck(stream, Mess.Header, pdu.COMPLETE, pdu.ACK_SUCCESS)
		if err != nil {
			errHand.LogError(err, "error sending Ack for completion")
			return err
		}

	} else if Mess.Header.Length < pdu.MAX_PDU_SIZE && Mess.Header.SeqNumber > 1 {
		upload.Buffer = append(upload.Buffer, Mess.Data...)
		upload.LastSeqNum = Mess.Header.SeqNumber
		upload.TotalBytes += uint32(len(Mess.Data))

		_, err = file.Write(upload.Buffer)
		if err != nil {
			errHand.LogError(err, "error writing file to server")
			s.sendError(stream, Mess.Header, pdu.WRITE_ERROR, "Error writing file to server")
			return err
		}
		delete(uploads, Mess.Header.TransactionID)
		log.Printf("[server] File %s (%d bytes) uploaded successfully to %s", filename, upload.TotalBytes, REPO)
		err := s.sendAck(stream, Mess.Header, pdu.COMPLETE, pdu.ACK_SUCCESS)
		if err != nil {
			errHand.LogError(err, "error sending Ack for completion")
			return err
		}

	} else {
		if Mess.Header.SeqNumber > 1 && Mess.Header.SeqNumber != upload.LastSeqNum+1 {
			errHand.LogError(errors.New(""), "received data messsage out of order")
			s.sendError(stream, Mess.Header, pdu.WRITE_ERROR, "Received out of order data message")
			return fmt.Errorf("received out of order data message")
		}
		upload.Buffer = append(upload.Buffer, Mess.Data...)
		upload.LastSeqNum = Mess.Header.SeqNumber
		upload.TotalBytes += uint32(len(Mess.Data))
		return nil
	}

	return nil
}

// handles any request to download a file from the server
func (s *Server) handleDownload(stream quic.Stream, conMessage *pdu.ControlMessage, token []byte) error {

	filepath := conMessage.Data

	_, err := os.Stat(REPO + string(filepath))
	if errors.Is(err, os.ErrNotExist) {
		s.sendError(stream, conMessage.Header, pdu.FILE_NOT_FOUND, "File not found on server")
		errHand.LogError(err, "file not found on server")
		return err
	}

	file, err := os.Open(REPO + string(filepath))
	if err != nil {
		s.sendError(stream, conMessage.Header, pdu.READ_ERROR, "File could not be read")
		errHand.LogError(err, "error opening file")
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
			errHand.LogError(err, "failed to read bytes from file buffer")
			return err
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
			errHand.LogError(err, "failed to create bytes from DataMessage")
			return err
		}

		// Pad the dataBytes to pdu.MAX_PDU_SIZE if necessary
		if len(dataBytes) < int(pdu.MAX_PDU_SIZE) {
			padding := make([]byte, pdu.MAX_PDU_SIZE-uint32(len(dataBytes)))
			dataBytes = append(dataBytes, padding...)
		}

		_, err = stream.Write(dataBytes)
		if err != nil {
			s.sendError(stream, conMessage.Header, pdu.READ_ERROR, "failed to send DataMessage")
			errHand.LogError(err, "failed to send DataMessage")
			return err
		}

		i++
	}
	err = s.sendAck(stream, conMessage.Header, pdu.COMPLETE, pdu.ACK_SUCCESS)
	if err != nil {
		s.sendError(stream, conMessage.Header, pdu.CONNECTION_INTERRUPTED, "failed to send AckMessage")
		errHand.LogError(err, "error sending Ack for successful download")
		return err
	}
	log.Printf("[server] File %s downloaded successfully. Waiting for client to send ack response...", filepath)
	return nil
}
