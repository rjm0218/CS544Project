package pdu

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
)

const (

	//Handshake states
	HANDSHAKE_INIT     uint8 = 1
	HANDSHAKE_RESPONSE uint8 = 2

	//Authentication types
	USER_PASSWORD = 1
	CERT          = 2

	//Option flags
	NO_FLAG    = 0x00 //no optional parameters
	FLAG_SYNC  = 0x01 //use synchronous mode
	FLAG_ASYNC = 0x02 //use asynchronous mode
	FLAG_COMPR = 0x04 //compress data before transfer
	FLAG_MULTI = 0x08 //use multiple streams
	FLAG_VALID = 0x10 //use checksum for data validation

	// PDU types
	DATA    = 0
	ACK     = 1
	CONTROL = 2
	ERROR   = 3

	// ACK Status
	ACK_SUCCESS          = 0
	ACK_RESEND_REQUESTED = 1
	ACK_FAILURE          = 2

	// Control codes
	START            = 1
	START_UPLOAD     = 2
	START_DOWNLOAD   = 3
	PAUSE_UPLOAD     = 4
	PAUSE_DOWNLOAD   = 5
	RESUME_UPLOAD    = 6
	RESUME_DOWNLOAD  = 7
	STOP_UPLOAD      = 8
	STOP_DOWNLOAD    = 9
	START_DELETION   = 10
	RESET            = 11
	CLOSE_CONNECTION = 12

	// Requested Op
	READ   = 1
	WRITE  = 2
	DELETE = 3

	// Transition states
	IDLE        = 0
	INITIATING  = 1
	UPLOADING   = 2
	DOWNLOADING = 3
	DELETING    = 4
	COMPLETE    = 5
	PAUSED      = 6

	// Error codes
	FILE_NOT_FOUND         = 1
	DIRECTORY_NOT_FOUND    = 2
	ACCESS_DENIED          = 3
	TIMEOUT                = 4
	CONNECTION_INTERRUPTED = 5
	INVALID_CONTROL_CODE   = 6
	WRITE_ERROR            = 7
	READ_ERROR             = 8
	UNKNOWN_ERROR          = 9

	//Data sizes for easier management
	HandHeadSize uint32 = 19
	HeaderSize   uint32 = 16
	DataSize     uint32 = 10
	AckSize      uint32 = 14
	ConSize      uint32 = 10
	ErrSize      uint32 = 9
	MAX_PDU_SIZE uint32 = 1024
)

var StartTranId uint32
var StartSeqNum uint32

type HandMessHeader struct {
	Type          uint8  `json:"type"`
	Version       uint32 `json:"version"`
	TransactionID uint32 `json:"transaction_id"`
	SeqNumber     uint32 `json:"seq_number"`
	Length        uint32 `json:"length"`
	Flags         uint16 `json:"flags"`
}

type HandMessage struct {
	Header   HandMessHeader `json:"header"`
	AuthType uint8          `json:"auth_type"`
	Data     string         `json:"data"`
}

// General header structure used by all messages
type MessHeader struct {
	Type          uint16 `json:"type"`
	TransactionID uint32 `json:"transaction_id"`
	SeqNumber     uint32 `json:"seq_number"`
	Length        uint32 `json:"length"`
}

// Data message structure
type DataMessage struct {
	Header      MessHeader `json:"header"`
	Checksum    uint32     `json:"checksum"`
	SeqNumber   uint32     `json:"seq_number"`
	RequestedOp uint8      `json:"requested_op"`
	Permissions uint8      `json:"permissions"`
	Data        []byte     `json:"data"`
}

// ACK message structure
type AckMessage struct {
	Header                     MessHeader `json:"header"`
	ReceivedTimestamp          uint64     `json:"received_timestamp"`
	AcknowledgedSequenceNumber uint32     `json:"acknowledged_sequence_number"`
	State                      uint8      `json:"state"`
	Status                     uint8      `json:"status"`
}

// Control message structure
type ControlMessage struct {
	Header           MessHeader `json:"header"`
	ControlTimestamp uint64     `json:"control_timestamp"`
	ControlCode      uint16     `json:"control_code"`
}

// Error message structure
type ErrorMessage struct {
	Header         MessHeader `json:"header"`
	ErrorTimestamp uint64     `json:"error_timestamp"`
	ErrorCode      uint8      `json:"error_code"`
	ErrorMessage   string     `json:"error_message"`
}

func (msg *DataMessage) CalculateChecksum() {
	msg.Checksum = crc32.ChecksumIEEE(msg.Data)
}

func MakePduBuffer() []byte {
	return make([]byte, MAX_PDU_SIZE)
}

func NewHandMessage(handType uint8, transaction_id uint32, seq_number uint32, authType uint8, data string) HandMessage {

	return HandMessage{
		Header: HandMessHeader{
			Type:          handType,
			Version:       1,
			TransactionID: StartTranId,
			SeqNumber:     seq_number + 1,
			Length:        HandHeadSize + 1 + uint32(len(data)),
			Flags:         NO_FLAG,
		},
		AuthType: authType,
		Data:     data,
	}
}

func HandMessHeaderFromBytes(data []byte) (*HandMessHeader, error) {
	header := &HandMessHeader{}
	err := json.Unmarshal(data, header)
	if err != nil {
		return nil, err
	}
	return header, nil
}

// Function to convert MessHeader to bytes
func HandMessHeaderToBytes(header HandMessHeader) ([]byte, error) {
	return json.Marshal(header)
}

// Convert HandMessage to bytes
func HandMessageToBytes(msg HandMessage) ([]byte, error) {
	return json.Marshal(msg)
}

func HandMessageFromBytes(raw []byte) (*HandMessage, error) {
	msg := &HandMessage{}
	err := json.Unmarshal(raw, msg)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// Function to convert MessHeader from bytes
func MessHeaderFromBytes(data []byte) (*MessHeader, error) {
	header := &MessHeader{}
	err := json.Unmarshal(data, header)
	if err != nil {
		return nil, err
	}
	return header, nil
}

// Function to convert MessHeader to bytes
func MessHeaderToBytes(header *MessHeader) ([]byte, error) {
	return json.Marshal(header)
}

func NewDataMessage(header MessHeader, seqNumber uint32, requestedOp uint8, permissions uint8, data []byte) *DataMessage {
	message := &DataMessage{
		Header:      header,
		SeqNumber:   seqNumber,
		RequestedOp: requestedOp,
		Permissions: permissions,
		Data:        data,
	}
	message.CalculateChecksum()
	message.Header.Length = uint32(20 + len(data)) // Update length to include header and data
	return message
}

func (msg *DataMessage) GetTypeAsString() string {
	switch msg.Header.Type {
	case DATA:
		return "***DATA"
	case ACK:
		return "****ACK"
	case CONTROL:
		return "**CONTROL"
	case ERROR:
		return "***ERROR"
	default:
		return "UNKNOWN"
	}
}

func (msg *DataMessage) ToJsonString() string {
	jsonData, err := json.MarshalIndent(msg, "", "    ")
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "{}"
	}
	return string(jsonData)
}

func DataMessageFromBytes(raw []byte) (*DataMessage, error) {
	msg := &DataMessage{}
	err := json.Unmarshal(raw, msg)
	if err != nil {
		return nil, err
	}
	if msg.Checksum != crc32.ChecksumIEEE(msg.Data) {
		return nil, errors.New("checksum mismatch")
	}
	return msg, nil
}

func DataMessageToBytes(msg *DataMessage) ([]byte, error) {
	return json.Marshal(msg)
}

// ACK message section
func NewAckMessage(header MessHeader, receivedTimestamp uint64, acknowledgedSequenceNumber uint32, state uint8, status uint8) *AckMessage {
	message := &AckMessage{
		Header:                     header,
		ReceivedTimestamp:          receivedTimestamp,
		AcknowledgedSequenceNumber: acknowledgedSequenceNumber,
		State:                      state,
		Status:                     status,
	}
	message.Header.Length = uint32(20) // Update length to include header and ACK message fields
	return message
}

func AckMessageFromBytes(raw []byte) (*AckMessage, error) {
	msg := &AckMessage{}
	err := json.Unmarshal(raw, msg)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func AckMessageToBytes(msg *AckMessage) ([]byte, error) {
	return json.Marshal(msg)
}

// Control message section
func NewControlMessage(header MessHeader, controlTimestamp uint64, controlCode uint16) *ControlMessage {
	message := &ControlMessage{
		Header:           header,
		ControlTimestamp: controlTimestamp,
		ControlCode:      controlCode,
	}
	message.Header.Length = uint32(20) // Update length to include header and control message fields
	return message
}

func ControlMessageFromBytes(raw []byte) (*ControlMessage, error) {
	msg := &ControlMessage{}
	err := json.Unmarshal(raw, msg)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func ControlMessageToBytes(msg *ControlMessage) ([]byte, error) {
	return json.Marshal(msg)
}

// Error message section
func NewErrorMessage(header MessHeader, errorTimestamp uint64, errorCode uint8, errorMessage string) *ErrorMessage {
	message := &ErrorMessage{
		Header:         header,
		ErrorTimestamp: errorTimestamp,
		ErrorCode:      errorCode,
		ErrorMessage:   errorMessage,
	}
	message.Header.Length = uint32(20 + len(errorMessage)) // Update length to include header and error message fields
	return message
}

func ErrorMessageFromBytes(raw []byte) (*ErrorMessage, error) {
	msg := &ErrorMessage{}
	err := json.Unmarshal(raw, msg)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func ErrorMessageToBytes(msg *ErrorMessage) ([]byte, error) {
	return json.Marshal(msg)
}
