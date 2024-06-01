package pdu

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
)

const (

	//Authentication types
	USER_PASSWORD = 1
	CERT          = 2

	//Option flags for future versions
	NO_FLAG    = 0x00 //no optional parameters
	FLAG_SYNC  = 0x01 //use synchronous mode
	FLAG_ASYNC = 0x02 //use asynchronous mode
	FLAG_COMPR = 0x04 //compress data before transfer
	FLAG_MULTI = 0x08 //use multiple streams
	FLAG_VALID = 0x10 //use checksum for data validation

	// PDU types
	DATA    uint8 = 0
	ACK     uint8 = 1
	CONTROL uint8 = 2
	ERROR   uint8 = 3

	//Handshake states
	HANDSHAKE_INIT     uint8 = 4
	HANDSHAKE_RESPONSE uint8 = 5

	// ACK Status
	ACK_SUCCESS          uint8 = 0
	ACK_RESEND_REQUESTED uint8 = 1
	ACK_FAILURE          uint8 = 2

	// Control codes
	START            uint8 = 1
	START_UPLOAD     uint8 = 2
	START_DOWNLOAD   uint8 = 3
	PAUSE_UPLOAD     uint8 = 4
	PAUSE_DOWNLOAD   uint8 = 5
	RESUME_UPLOAD    uint8 = 6
	RESUME_DOWNLOAD  uint8 = 7
	STOP_UPLOAD      uint8 = 8
	STOP_DOWNLOAD    uint8 = 9
	START_DELETION   uint8 = 10
	RESET            uint8 = 11
	CLOSE_CONNECTION uint8 = 12

	// Requested Op
	READ   uint8 = 1
	WRITE  uint8 = 2
	DELETE uint8 = 3

	// Transition states
	IDLE        uint8 = 0
	INITIATING  uint8 = 1
	UPLOADING   uint8 = 2
	DOWNLOADING uint8 = 3
	DELETING    uint8 = 4
	COMPLETE    uint8 = 5
	PAUSED      uint8 = 6

	// Error codes
	FILE_NOT_FOUND         uint8 = 1
	DIRECTORY_NOT_FOUND    uint8 = 2
	INVALID_CRED           uint8 = 3
	ACCESS_DENIED          uint8 = 4
	TIMEOUT                uint8 = 5
	CONNECTION_INTERRUPTED uint8 = 6
	INVALID_CONTROL_CODE   uint8 = 7
	WRITE_ERROR            uint8 = 8
	READ_ERROR             uint8 = 9
	UNKNOWN_ERROR          uint8 = 10

	//Data sizes for easier management
	HandHeadSize uint32 = 24
	HandMessSize uint32 = 1
	HeaderSize   uint32 = 24
	AckSize      uint32 = 14
	ConSize      uint32 = 10
	ErrSize      uint32 = 9
	MAX_PDU_SIZE uint32 = 1024

	//Version
	Version uint32 = 1
)

var StartTranId uint32 = 0
var StartSeqNum uint32 = 0

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
	Data     []byte         `json:"data"`
}

// General header structure used by all messages
type MessHeader struct {
	Type          uint8  `json:"type"`
	TransactionID uint32 `json:"transaction_id"`
	SeqNumber     uint32 `json:"seq_number"`
	Length        uint32 `json:"length"`
	Token         []byte `json:"token"`
}

// Data message structure
type DataMessage struct {
	Header      MessHeader `json:"header"`
	Checksum    uint32     `json:"checksum"`
	RequestedOp uint8      `json:"requested_op"`
	Filename    []byte     `json:"filename"`
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
	ControlCode      uint8      `json:"control_code"`
	Data             []byte     `json:"data"`
}

// Error message structure
type ErrorMessage struct {
	Header         MessHeader `json:"header"`
	ErrorTimestamp uint64     `json:"error_timestamp"`
	ErrorCode      uint8      `json:"error_code"`
	ErrorMessage   string     `json:"error_message"`
}

// make a byte array to hold the pdu
func MakePduBuffer() []byte {
	return make([]byte, MAX_PDU_SIZE)
}

// remove any padding added to make the pdu
func RemovePadding(data []byte) []byte {
	// Find the index of the last non-null byte
	lastNonNullIndex := len(data) - 1
	for lastNonNullIndex >= 0 && data[lastNonNullIndex] == 0 {
		lastNonNullIndex--
	}

	// Return the slice without the padding bytes
	return data[:lastNonNullIndex+1]
}

// extract the raw json message from the raw bytes
func GetMessage(raw []byte) (json.RawMessage, error) {
	data := RemovePadding(raw)
	decoder := json.NewDecoder(bytes.NewReader(data))
	var msg json.RawMessage
	err := decoder.Decode(&msg)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// extract the message type from the json message
func ExtractMessageType(raw json.RawMessage) (uint8, error) {
	var temp struct {
		Header struct {
			Type uint8 `json:"type"`
		} `json:"header"`
	}
	err := json.Unmarshal(raw, &temp)
	if err != nil {
		return 0, err
	}
	return temp.Header.Type, nil
}

// create a new handshake message
func NewHandMessage(handType uint8, transaction_id uint32, seq_number uint32, authType uint8, data []byte) HandMessage {

	return HandMessage{
		Header: HandMessHeader{
			Type:          handType,
			Version:       Version,
			TransactionID: StartTranId,
			SeqNumber:     seq_number + 1,
			Length:        HandHeadSize + 9,
			Flags:         NO_FLAG,
		},
		AuthType: authType,
		Data:     data,
	}
}

// return the json string for the handshake message
func (msg *HandMessage) ToJsonStringHand() string {
	jsonData, err := json.MarshalIndent(msg, "", "    ")
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "{}"
	}
	return string(jsonData)
}

// Convert HandMessage to bytes
func HandMessageToBytes(msg HandMessage) ([]byte, error) {
	return json.Marshal(msg)
}

// Convert HandMessage from bytes
func HandMessageFromBytes(raw []byte) (*HandMessage, error) {

	msg := &HandMessage{}
	err := json.Unmarshal(raw, msg)
	if err != nil {
		fmt.Printf("Error unmarshaling: %s\n", err) // Print specific error
		return nil, err
	}
	return msg, nil
}

// Data message checksum calculation
func (msg *DataMessage) CalculateChecksum() {
	msg.Checksum = crc32.ChecksumIEEE(msg.Data)
}

// Make a buffer based on header size to limit data to max pdu size
func MakeDataBuffer(messSize uint32) []byte {
	return make([]byte, MAX_PDU_SIZE-messSize)
}

// Calculate the overhead of the DataMessage based on the token and filename
func CalculateDataOverhead(token []byte, filename []byte) uint32 {
	// Create a sample DataMessage with all fields populated except Data
	sampleHeader := MessHeader{
		Type:          DATA,
		TransactionID: 1,
		SeqNumber:     1,
		Length:        0, // This will be updated later
		Token:         token,
	}

	sampleDataMessage := DataMessage{
		Header:      sampleHeader,
		Checksum:    0, // Checksum will be calculated later
		RequestedOp: WRITE,
		Filename:    filename,
		Data:        nil, // No data in the sample message
	}

	// Marshal the sample DataMessage to JSON bytes
	marshaledBytes, err := json.Marshal(sampleDataMessage)
	if err != nil {
		// Handle error
		return 0
	}

	// The length of the marshaled bytes is the DataOverhead
	dataOverhead := uint32(len(marshaledBytes))
	dataOverhead += 230 //extra buffer for Marshalling data

	return dataOverhead
}

// create a new data message with the requested operation, filename and data
func NewDataMessage(header MessHeader, requestedOp uint8, filename []byte, data []byte) *DataMessage {
	message := &DataMessage{
		Header:      header,
		RequestedOp: requestedOp,
		Filename:    filename,
		Data:        data,
	}

	message.CalculateChecksum()
	return message
}

// return the message type as a string
func GetTypeAsString(messType uint8) string {
	switch messType {
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

// return the data message as a json string
func (msg *DataMessage) ToJsonString() string {
	jsonData, err := json.MarshalIndent(msg, "", "    ")
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "{}"
	}
	return string(jsonData)
}

// convert bytes to DataMessage
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

// convert DataMessage to bytes
func DataMessageToBytes(msg *DataMessage) ([]byte, error) {
	return json.Marshal(msg)
}

/////// ACK message section

// create a new ack message
func NewAckMessage(header interface{}, receivedTimestamp uint64, acknowledgedSequenceNumber uint32, state uint8, status uint8, data []byte) (interface{}, error) {
	var message interface{}
	switch h := header.(type) {
	case HandMessHeader:
		message = &HandMessage{
			Header:   h,
			AuthType: USER_PASSWORD,
			Data:     data,
		}
		return message, nil
	case MessHeader:
		message = &AckMessage{
			Header:                     h,
			ReceivedTimestamp:          receivedTimestamp,
			AcknowledgedSequenceNumber: acknowledgedSequenceNumber,
			State:                      state,
			Status:                     status,
		}
		return message, nil
	default:
		return nil, errors.New("invalid header type")
	}
}

// get ack message from raw bytes
func AckMessageFromBytes(raw []byte) (*AckMessage, error) {
	msg := &AckMessage{}
	err := json.Unmarshal(raw, msg)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// convert AckMessage to bytes
func AckMessageToBytes(msg interface{}) ([]byte, error) {
	return json.Marshal(msg)
}

// convert AckMessage to json string
func ToJsonStringAck(msg interface{}) string {
	jsonData, err := json.MarshalIndent(msg, "", "    ")
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "{}"
	}
	return string(jsonData)
}

//////// Control message section

// create a new control message
func NewControlMessage(header MessHeader, controlTimestamp uint64, controlCode uint8, filepath []byte) *ControlMessage {
	message := &ControlMessage{
		Header:           header,
		ControlTimestamp: controlTimestamp,
		ControlCode:      controlCode,
		Data:             filepath,
	}

	return message
}

// get control message from raw bytes
func ControlMessageFromBytes(raw []byte) (*ControlMessage, error) {
	msg := &ControlMessage{}
	err := json.Unmarshal(raw, msg)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// convert ControlMessage to bytes
func ControlMessageToBytes(msg *ControlMessage) ([]byte, error) {
	return json.Marshal(msg)
}

// get the control type as a string
func GetControlAsString(controlType uint8) string {

	switch controlType {
	case START:
		return "START"
	case START_UPLOAD:
		return "START_UPLOAD"
	case START_DOWNLOAD:
		return "START_DOWNLOAD"
	case PAUSE_UPLOAD:
		return "PAUSE_UPLOAD"
	case PAUSE_DOWNLOAD:
		return "PAUSE_DOWNLOAD"
	case RESUME_UPLOAD:
		return "RESUME_UPLOAD"
	case RESUME_DOWNLOAD:
		return "RESUME_DOWNLOAD"
	case STOP_UPLOAD:
		return "STOP_UPLOAD"
	case STOP_DOWNLOAD:
		return "STOP_DOWNLOAD"
	case START_DELETION:
		return "START_DELETION"
	case RESET:
		return "RESET"
	case CLOSE_CONNECTION:
		return "CLOSE_CONNECTION"
	default:
		return "UNKNOWN"
	}
}

///////// Error message section

// create a new error message
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

// get error message from raw bytes
func ErrorMessageFromBytes(raw []byte) (*ErrorMessage, error) {
	msg := &ErrorMessage{}
	err := json.Unmarshal(raw, msg)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// convert ErrorMessage to bytes
func ErrorMessageToBytes(msg *ErrorMessage) ([]byte, error) {
	return json.Marshal(msg)
}
