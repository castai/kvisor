package main

type param struct {
	name      string
	paramType ArgType
}

type eventDefinition struct {
	event  string
	params []param
}

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
	protoDNST
	protoSSHT
)

// These types don't match the ones defined in the ebpf code since they are not being used by syscalls arguments.
// They have their own set of value to avoid collision in the future.
const (
	argsArrT ArgType = iota + 0x80
	boolT
)

var argTypeNames = map[ArgType]string{
	noneT:      "noneT",
	intT:       "intT",
	uintT:      "uintT",
	longT:      "longT",
	ulongT:     "ulongT",
	offT:       "offT",
	modeT:      "modeT",
	devT:       "devT",
	sizeT:      "sizeT",
	pointerT:   "pointerT",
	strT:       "strT",
	strArrT:    "strArrT",
	sockAddrT:  "sockAddrT",
	bytesT:     "bytesT",
	u16T:       "u16T",
	credT:      "credT",
	intArr2T:   "intArr2T",
	uint64ArrT: "uint64ArrT",
	u8T:        "u8T",
	timespecT:  "timespecT",
	tupleT:     "tupleT",
	argsArrT:   "argsArrT",
	boolT:      "boolT",
	protoDNST:  "protoDNST",
	protoSSHT:  "protoSSHT",
}

func (a ArgType) String() string {
	return argTypeNames[a]
}
