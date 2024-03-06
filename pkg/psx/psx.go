package psx

import "syscall"

func Syscall3(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return
}

func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return
}
