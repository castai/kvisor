package types

type EventType string

func (e EventType) String() string {
	return string(e)
}

func (e EventType) HumanString() string {
	switch e {
	case EventExec:
		return "Exec"
	case EventDNS:
		return "DNS"
	case EventFileChange:
		return "File Change"
	case EventFileOpen:
		return "File Open"
	case EventTCPPacket:
		return "TCP Packet Transmission"
	case EventTCPAccept:
		return "TCP Accept"
	case EventTCPConnect:
		return "TCP Connection"
	case EventTCPListen:
		return "TCP Listen"
	case EventTCPListenClose:
		return "TCP Listen Close"
	case EventTCPClose:
		return "TCP Connection Close"
	case EventTCPSample:
		return "TCP Sample"
	case EventTCPSendReset:
		return "TCP Send Reset"
	case EventTCPReceiveReset:
		return "TCP Receive Reset"
	case EventTCPRetransmitSkb:
		return "TCP Retransmit Socket Buffer"
	case EventTCPConnectError:
		return "TCP Connection Error"
	case EventSocketStateChange:
		return "Socket State Change"
	case EventImagePullFailed:
		return "Image Pull Failure"
	case EventProcessFailed:
		return "Process Execution Failure"
	case EventProcessOOMKilled:
		return "Process Out of Memory Killed"
	case EventMagicWrite:
		return "Magic Write"
	case EventStdioViaSocket:
		return "Stdio via Socket"
	case EventTtyWrite:
		return "TTY write"
	case EventSOCKS5Detected:
		return "SOCKS5 Proxy detected"
	case EventSSH:
		return "SSH detected"
	default:
		return EventUnknown.String()
	}
}

const (
	EventExec              EventType = "exec"
	EventDNS               EventType = "dns"
	EventFileChange        EventType = "file_change"
	EventFileOpen          EventType = "file_open"
	EventTCPPacket         EventType = "tcp_packet"
	EventTCPAccept         EventType = "tcp_accept"
	EventTCPConnect        EventType = "tcp_connect"
	EventTCPListen         EventType = "tcp_listen"
	EventTCPListenClose    EventType = "tcp_listen_close"
	EventTCPClose          EventType = "tcp_close"
	EventTCPSample         EventType = "tcp_sample"
	EventTCPSendReset      EventType = "tcp_send_reset"
	EventTCPReceiveReset   EventType = "tcp_receive_reset"
	EventTCPRetransmitSkb  EventType = "tcp_retransmit_skb"
	EventTCPConnectError   EventType = "tcp_connect_error"
	EventSocketStateChange EventType = "socket_state_change"
	EventImagePullFailed   EventType = "image_pull_failed"
	EventProcessFailed     EventType = "process_failed"
	EventProcessOOMKilled  EventType = "process_oom_killed"
	EventMagicWrite        EventType = "magic_write"
	EventStdioViaSocket    EventType = "stdio_via_socket"
	EventSOCKS5Detected    EventType = "socks5_detected"
	EventTtyWrite          EventType = "tty_write"
	EventSSH               EventType = "ssh"
	EventUnknown           EventType = "unknown"
)
