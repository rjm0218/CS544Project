package client

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"CS544PROJECT/pkg/pdu"

	"github.com/quic-go/quic-go"
)

const (
	LOCAL = "./local/"
)

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
	var byte_total int = 0

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

		byte_total += len(dataBytes)

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

	log.Printf("[client] finished sending file of size %d. Waiting for server to send ack...", byte_total)
	return nil
}

// handle the downloading of a file from the server
func (c *Client) downloadFile(stream quic.Stream, fileName string, transaction_id uint32, seq_number uint32) error {

	controlHeader := pdu.MessHeader{
		Type:          pdu.CONTROL,
		TransactionID: transaction_id,
		SeqNumber:     seq_number,
		Length:        pdu.HeaderSize + pdu.ConSize,
		Token:         c.token,
	}

	controlMsg := pdu.NewControlMessage(controlHeader, uint64(time.Now().UnixNano()), pdu.START_DOWNLOAD, []byte(fileName))
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

	filePath := LOCAL + fileName
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}

	defer file.Close()
	var dataMess pdu.DataMessage
	data_buffer := pdu.MakePduBuffer()
	for {

		n, err := stream.Read(data_buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read bytes from file buffer: %w", err)
		} else if err == io.EOF && n == 0 {
			break
		}

		// Get mesasage
		msg, err := pdu.GetMessage(data_buffer[:n])
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
				return nil
			} else if errMess.ErrorCode == pdu.READ_ERROR {
				return fmt.Errorf("[client] %s", errMess.ErrorMessage)
			}
			return fmt.Errorf("server sent error message")
		} else if headtype == pdu.ACK {
			status, err := c.handleAck(msg)
			if err != nil {
				return err
			} else if status == pdu.ACK_SUCCESS {
				log.Printf("[client] received Ack signaling download complete")
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

	err = c.sendAck(stream, dataMess.Header, pdu.COMPLETE, pdu.ACK_SUCCESS)

	if err != nil {
		return fmt.Errorf("failed to send AckMessage: %w", err)
	} else {
		log.Printf("[client] Download successful. %s downloaded to %s", fileName, LOCAL)
		return nil
	}

}
