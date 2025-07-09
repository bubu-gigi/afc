package utils

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
)

func CreateOutputFile(file string)*os.File {
  base := filepath.Base(file)
  fileCreated, err := os.Create("output/" + removeFileExtention(base) + ".csv")
	if err != nil {
		fmt.Printf("Error creating the csv file: %v\n", err)
		os.Exit(1)
	}
  return fileCreated
}

func removeFileExtention(file string) string {
  parts := strings.Split(file, ".")
  if len(parts) <= 1 {
    return file 
  }
  return strings.Join(parts[:len(parts)-1], ".")
}


func CheckNullUint16(v uint16) {
	if v != 0 {
		log.Fatal("link.header -> Error: Reserved1 not null")
	}
}

func CheckNullUint32(v uint32) {
	if v != 0 {
		log.Fatal("link.header -> Error: Reserved2 or Reserved3 not null")
	}
}

func FindNullTerminator(data []byte) int {
	for i, b := range data {
		if b == 0 {
			return i
		}
	}
	return len(data) 
}

func FindNullTerminatorUTF16(data []byte) int {
	for i := 0; i+1 < len(data); i += 2 {
		if data[i] == 0 && data[i+1] == 0 {
			return i
		}
	}
	return len(data)
}

func DecodeUTF16String(b []byte) string {
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16))
}

func FileTimeToString(ft uint64) string {
	const ticksPerSecond = 10000000
	const epochDifference = 11644473600 

	seconds := int64(ft / ticksPerSecond)
	unix := seconds - epochDifference
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04:05")
}

func FormatMapKeys(m map[string]bool) string {
	var result []string
	for k, v := range m {
		if v {
			result = append(result, k)
		}
	}
	return strings.Join(result, "; ")
}

func IsPrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
