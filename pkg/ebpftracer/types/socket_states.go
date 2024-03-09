package types

type TCPSocketState uint32

const (
	TCP_STATE_UNKNOWN      TCPSocketState = 0
	TCP_STATE_ESTABLISHED  TCPSocketState = 1
	TCP_STATE_SYN_SENT     TCPSocketState = 2
	TCP_STATE_SYN_RECV     TCPSocketState = 3
	TCP_STATE_FIN_WAIT1    TCPSocketState = 4
	TCP_STATE_FIN_WAIT2    TCPSocketState = 5
	TCP_STATE_TIME_WAIT    TCPSocketState = 6
	TCP_STATE_CLOSE        TCPSocketState = 7
	TCP_STATE_CLOSE_WAIT   TCPSocketState = 8
	TCP_STATE_LAST_ACK     TCPSocketState = 9
	TCP_STATE_LISTEN       TCPSocketState = 10
	TCP_STATE_CLOSING      TCPSocketState = 11
	TCP_STATE_NEW_SYN_RECV TCPSocketState = 12
	TCP_STATE_MAX_STATES   TCPSocketState = 13
)

type SocketState struct {
	OldState TCPSocketState
	NewState TCPSocketState
}
