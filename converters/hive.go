package converters

import (
	utils "afc/lib"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	regparser "www.velocidex.com/golang/regparser"
)

var (
	f        *os.File
	registry *regparser.Registry
	err      error
	writer   *csv.Writer
	root     *regparser.CM_KEY_NODE
	visited = make(map[string]bool)
)

func ConvertRegistryHiveToCsv(files []string) {
	for _, file := range files {
		convertHive(file)
	}
}

// a registry hive file is a file with a root key and multiple subkeys as a generic tree
// they follow the format REGF and start with 4096 byte with file's info
func convertHive(file string) {

	f, err = os.Open(file)
	if err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}
	defer f.Close()

	registry, err = regparser.NewRegistry(f)
	if err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}

	// check the existence of root key
	root = registry.OpenKey("")
	if root == nil {
		fmt.Println("Error: Root key not found")
		os.Exit(1)
	}

	fileOut := utils.CreateOutputFile(file)
	defer fileOut.Close()

	writer = csv.NewWriter(fileOut)
	defer writer.Flush()

	writer.Write([]string{"Path", "LastWrite", "Name", "Type", "Value"})
	walk(root, `\`)
}

func walk(key *regparser.CM_KEY_NODE, path string) {
	if visited[path] {
		return
	}
	visited[path] = true
	lastWrite := key.LastWriteTime().UTC().Format(time.RFC3339)

	for _, value := range key.Values() {
		name := value.Name()
		if name == "" {
			name = "(default)"
		}

		valType := regTypeString(value.Type())
		valData := getValueData(value, f)

		writer.Write([]string{
			path,
			lastWrite,
			name,
			valType,
			valData,
		})
	}
	for _, subkey := range key.Subkeys() {
		subPath := filepath.Join(path, subkey.Name())
		walk(subkey, subPath)
	}
}

func getValueData(val *regparser.CM_KEY_VALUE, reader io.ReaderAt) string {
	dataOffset := int64(val.Data())
	dataLength := val.DataLength()
	dataType := val.Type()

	buf := make([]byte, dataLength)
	_, err := reader.ReadAt(buf, dataOffset+0x1000) // add base hive's offset 
	if err != nil {
		return fmt.Sprintf("Error reading: %v", err)
	}

	switch dataType {
	case 1: // REG_SZ o REG_EXPAND_SZ
		return regparser.UTF16BytesToUTF8(buf, binary.LittleEndian)

	case 2:
		value := regparser.UTF16BytesToUTF8(buf, binary.LittleEndian)
		// we try to replace the name of the env var with the actual value
		// we must be in the system
		expanded := os.ExpandEnv(value)
		if expanded == "" {
			return value + "VNF" // ValueNotFound
		} else {
			return expanded 
		}

	case 3: // REG_BINARY
		return fmt.Sprintf("%X", buf)

	case 4: // REG_DWORD
		if len(buf) >= 4 {
			return fmt.Sprintf("%d", binary.LittleEndian.Uint32(buf))
		}

	case 11: // REG_QWORD
		if len(buf) >= 8 {
			return fmt.Sprintf("%d", binary.LittleEndian.Uint64(buf))
		}

	case 7: // REG_MULTI_SZ
		str := regparser.UTF16BytesToUTF8(buf, binary.LittleEndian)
		return strings.Join(strings.Split(str, "\x00"), "|")

	default:
		return fmt.Sprintf("Type not handled (%d): %X", dataType, buf)
	}
	return ""
}

func regTypeString(typ uint32) string {
	switch typ {
	case 1:
		return "REG_SZ" // A null-terminated string. It's either a Unicode or an ANSI string.
	case 2:
		return "REG_EXPAND_SZ" // A null-terminated string that contains unexpanded references to environment variables, for example, %PATH%. It's either a Unicode or an ANSI string.
	case 3:
		return "REG_BINARY" // Binary data in any form.
	case 4:
		return "REG_DWORD" // A 32-bit number.
	case 5:
		return "REG_DWORD_BIG_ENDIAN" // A 32-bit number in little-endian format
	case 6:
		return "REG_LINK" // A null-terminated Unicode string that contains the target path of a symbolic link that was created by calling the RegCreateKeyEx function with REG_OPTION_CREATE_LINK.
	case 7:
		return "REG_MULTI_SZ" // A sequence of null-terminated strings, terminated by an empty string (\0). 
	case 11:
		return "REG_QWORD" // A 64-bit number.
	default:
		return fmt.Sprintf("UNKNOWN (%d)", typ)
	}
}


// https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types