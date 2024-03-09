package ebpftracer

type ArgType uint8

const (
	noneT ArgType = iota
	intT
	uintT
	longT
	ulongT
	offT
	modeT
	devT
	sizeT
	pointerT
	strT
	strArrT
	sockAddrT
	bytesT
	u16T
	credT
	intArr2T
	uint64ArrT
	u8T
	timespecT
	tupleT
)

// These types don't match the ones defined in the ebpf code since they are not being used by syscalls arguments.
// They have their own set of value to avoid collision in the future.
const (
	argsArrT ArgType = iota + 0x80
	boolT
)

func getParamType(paramType string) ArgType {
	switch paramType {
	case "int", "pid_t", "uid_t", "gid_t", "mqd_t", "clockid_t", "const clockid_t", "key_t", "key_serial_t", "timer_t":
		return intT
	case "unsigned int", "u32":
		return uintT
	case "long":
		return longT
	case "unsigned long", "u64":
		return ulongT
	case "bool":
		return boolT
	case "off_t", "loff_t":
		return offT
	case "mode_t":
		return modeT
	case "dev_t":
		return devT
	case "size_t":
		return sizeT
	case "void*", "const void*":
		return pointerT
	case "char*", "const char*":
		return strT
	case "const char*const*": // used by execve(at) argv and env
		return strArrT
	case "const char**": // used by sched_process_exec argv and envp
		return argsArrT
	case "const struct sockaddr*", "struct sockaddr*":
		return sockAddrT
	case "bytes":
		return bytesT
	case "int[2]":
		return intArr2T
	case "slim_cred_t":
		return credT
	case "umode_t":
		return u16T
	case "u8":
		return u8T
	case "unsigned long[]", "[]HookedSymbolData":
		return uint64ArrT
	case "struct timespec*", "const struct timespec*":
		return timespecT
	case "tuple":
		return tupleT
	default:
		// Default to pointer (printed as hex) for unsupported types
		return pointerT
	}
}
