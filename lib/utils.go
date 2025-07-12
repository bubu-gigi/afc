package utils

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"

	"www.velocidex.com/golang/go-ntfs/parser"
)

func CreateOutputFile(file string) *os.File {
	relPath, err := filepath.Rel("./data", file)
	if err != nil {
		fmt.Printf("Error resolving relative path: %v\n", err)
		os.Exit(1)
	}

	outputPath := filepath.Join("output", relPath)

	outputPath = strings.TrimSuffix(outputPath, filepath.Ext(outputPath)) + ".csv"

	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("Error creating output directories: %v\n", err)
		os.Exit(1)
	}

	fileCreated, err := os.Create(outputPath)
	if err != nil {
		fmt.Printf("Error creating the csv file: %v\n", err)
		os.Exit(1)
	}

	return fileCreated
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



//VELOCIDEX

func GetMFTEntry(ntfs_ctx *parser.NTFSContext, filename string) (*parser.MFT_ENTRY, error) {
	mft_idx, _, _, _, err := parser.ParseMFTId(filename)
	if err == nil {
		// Access by mft id (e.g. 1234-128-6)
		return ntfs_ctx.GetMFT(mft_idx)
	} else {
		// Access by filename.
		dir, err := ntfs_ctx.GetMFT(5)
		if err != nil {
			return nil, err
		}

		return dir.Open(ntfs_ctx, filename)
	}
}


func ReadFullUnicodeString(f *os.File) (string, error) {
	var charCount uint16
	err := binary.Read(f, binary.LittleEndian, &charCount)
	if err != nil {
		return "", err
	}

	if charCount == 0 {
		return "", nil
	}

	byteCount := int(charCount) * 2
	buf := make([]byte, byteCount)
	_, err = io.ReadFull(f, buf)
	if err != nil {
		return "", err
	}

	utf16buf := make([]uint16, charCount)
	for i := 0; i < int(charCount); i++ {
		utf16buf[i] = binary.LittleEndian.Uint16(buf[i*2 : i*2+2])
	}

	if charCount > 0 && utf16buf[charCount-1] == 0 {
		utf16buf = utf16buf[:charCount-1]
	}

	return string(utf16.Decode(utf16buf)), nil
}