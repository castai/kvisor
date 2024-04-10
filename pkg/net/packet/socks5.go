package packet

import (
	"encoding/binary"
	"errors"
)

type SOCKS5MessagesType uint8

const (
	SOCKS5MessageUnknown SOCKS5MessagesType = iota
	SOCKS5MessageInitialClientRequest
	SOCKS5MessageInitialServerResponse

	// they request and reply message look identical on the wire
	// so hence we need to share a constant
	SOCKS5MessageRequestOrReply
)

var socks5MessageTypeNames = map[SOCKS5MessagesType]string{
	SOCKS5MessageInitialClientRequest:  "InitialClientRequest",
	SOCKS5MessageInitialServerResponse: "InitialServerResponse",
	SOCKS5MessageRequestOrReply:        "RequestOrReply",
}

func (m SOCKS5MessagesType) String() string {
	if name, found := socks5MessageTypeNames[m]; found {
		return name
	}

	return "Unknown"
}

type SOCKS5AddressType uint8

const (
	SOCKS5AddressTypeIPv4       SOCKS5AddressType = 0x01
	SOCKS5AddressTypeDomainName SOCKS5AddressType = 0x03
	SOCKS5AddressTypeIPv6       SOCKS5AddressType = 0x04
)

var socks5SAddressTypeNames = map[SOCKS5AddressType]string{
	SOCKS5AddressTypeIPv4:       "IPv4",
	SOCKS5AddressTypeDomainName: "DomainName",
	SOCKS5AddressTypeIPv6:       "IPv6",
}

func (a SOCKS5AddressType) String() string {
	if name, found := socks5SAddressTypeNames[a]; found {
		return name
	}

	return "Unknown"
}

type SOCKS5Message interface {
	internal()
	MessageType() SOCKS5MessagesType
}

type SOCKS5InitialClientRequest struct{}

func (SOCKS5InitialClientRequest) internal() {}
func (SOCKS5InitialClientRequest) MessageType() SOCKS5MessagesType {
	return SOCKS5MessageInitialClientRequest
}

type SOCKS5InitialServerResponse struct{}

func (SOCKS5InitialServerResponse) internal() {}
func (SOCKS5InitialServerResponse) MessageType() SOCKS5MessagesType {
	return SOCKS5MessageInitialServerResponse
}

type SOCKS5RequestOrReply struct {
	CmdOrReply  uint8
	AddressType SOCKS5AddressType
	Address     []byte // can either be a domain name, ipv4 or ipv6. check the address type to know how to parse it
	Port        uint16
}

func (SOCKS5RequestOrReply) internal() {}
func (SOCKS5RequestOrReply) MessageType() SOCKS5MessagesType {
	return SOCKS5MessageRequestOrReply
}

var (
	ErrSOCKS5InvalidMessage     = errors.New("invalid socks5 message")
	ErrSOCKS5InvalidVersion     = errors.New("invalid version set in socks5 payload")
	ErrSOCKS5InvalidAddressType = errors.New("invalid address type")
)

// ParseSOCKS5 tries to parses the given data based on https://datatracker.ietf.org/doc/html/rfc1928
func ParseSOCKS5(data []byte) (SOCKS5Message, error) {
	if len(data) < 2 {
		return nil, ErrSOCKS5InvalidMessage
	}

	// socks5 messages always start with the number 5
	if data[0] != 0x05 {
		return nil, ErrSOCKS5InvalidVersion
	}

	// only the initial server response matches a len of 2
	if len(data) == 2 {
		return SOCKS5InitialServerResponse{}, nil
	}

	// the client sends a message with potential methods it can connect with. the second field
	// gives the number of methods. if the message is the same length as the number of message + 2
	// (since the first two bytes contain other info), we should have an initial client request.
	// this could in theory clash with client request/server response , but is rather unlikely
	if int(data[1]+2) == len(data) {
		return SOCKS5InitialClientRequest{}, nil
	}

	// the request/response needs more than 4 bytes, but we use at least 4 for parsing
	if len(data) < 4 {
		return nil, ErrSOCKS5InvalidMessage
	}

	// the third byte is reserved to be 0x00 in both request and response
	if data[2] != 0x00 {
		return nil, ErrSOCKS5InvalidMessage
	}
	addressType := SOCKS5AddressType(data[3])

	switch addressType {
	case SOCKS5AddressTypeIPv4:
		// 4 bytes protocol + 4 bytes ipv4 + 2 bytes port = 10 bytes
		if len(data) != 10 {
			return nil, ErrSOCKS5InvalidMessage
		}

		return SOCKS5RequestOrReply{
			CmdOrReply:  data[1],
			AddressType: addressType,
			Address:     data[4:8],
			Port:        binary.BigEndian.Uint16(data[8:]),
		}, nil

	case SOCKS5AddressTypeIPv6:
		// 4 bytes protocol + 16 bytes ipv6 + 2 bytes port = 22 bytes
		if len(data) != 22 {
			return nil, ErrSOCKS5InvalidMessage
		}

		return SOCKS5RequestOrReply{
			CmdOrReply:  data[1],
			AddressType: addressType,
			Address:     data[4:20],
			Port:        binary.BigEndian.Uint16(data[20:]),
		}, nil
	case SOCKS5AddressTypeDomainName:
		// first byte in addr contains domain name length
		if len(data) < 5 {
			return nil, ErrSOCKS5InvalidMessage
		}
		numChars := int(data[4])

		// 4 bytes protocol + 1 byte len + num chars + 2 bytes port
		if len(data) != 4+1+numChars+2 {
			return nil, ErrSOCKS5InvalidMessage
		}

		return SOCKS5RequestOrReply{
			CmdOrReply:  data[1],
			AddressType: addressType,
			Address:     data[5 : 5+numChars],
			Port:        binary.BigEndian.Uint16(data[5+numChars:]),
		}, nil
	default:
		return nil, ErrSOCKS5InvalidAddressType
	}
}
