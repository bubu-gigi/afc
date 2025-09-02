package converters

import (
	"afc/config"
	"afc/flags"
	utils "afc/lib"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	regparser "www.velocidex.com/golang/regparser"
)

const flagHasVirtual = 0x20

func ConvertRegistryHiveToCsv(files []string, cfg *config.Config, opts *flags.GlobalOptions) {
	for _, file := range files {
		if err := convertHive(file, cfg, opts); err != nil {
			log.Printf("[ERROR] convert hive: file=%q err=%v", file, err)
		}
	}
	fmt.Println("hive done")
}

func convertHive(file string, cfg *config.Config, opts *flags.GlobalOptions) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("cannot open registry hive %s: %w", file, err)
	}
	defer f.Close()

	registry, err := regparser.NewRegistry(f)
	if err != nil {
		return fmt.Errorf("failed to parse registry hive %s: %w", file, err)
	}
	root := registry.OpenKey("")
	if root == nil {
		return fmt.Errorf("root key not found in registry hive %s", file)
	}

	headers := []string{
		"Path", "LastWrite", "Name", "Type", "Value",
		"ClassName", "SecurityOffset", "Flags",
		"SubkeyCount", "ValueCount", "HasVirtual",
	}

	var rows [][]string
	rows = make([][]string, 0, 8192) // preallocazione conservativa

	visited := make(map[string]bool)

	// buffer riutilizzabile per class name
	var classBuf []byte

	var walk func(*regparser.CM_KEY_NODE, string)
	walk = func(key *regparser.CM_KEY_NODE, path string) {
		if key == nil || path == "" {
			return
		}
		if visited[path] {
			return
		}
		visited[path] = true

		lastWrite := key.LastWriteTime().UTC().Format(time.RFC3339)

		className := ""
		if classLen := int(key.ClassLength()); classLen > 0 {
			if cap(classBuf) < classLen {
				classBuf = make([]byte, classLen)
			}
			classBuf = classBuf[:classLen]
			off := int64(key.Class()) + 0x1000
			if _, err := f.ReadAt(classBuf, off); err == nil {
				className = strings.TrimRight(regparser.UTF16BytesToUTF8(classBuf, binary.LittleEndian), "\x00")
			}
		}

		flags := key.Flags()
		hasVirtual := (flags & flagHasVirtual) != 0
		securityOffset := "0x" + strconv.FormatUint(uint64(key.Security()), 16)

		subkeys := key.Subkeys()
		values := key.Values()
		subkeyCount := len(subkeys)
		valueCount := len(values)

		for _, value := range values {
			name := value.Name()
			if name == "" {
				name = "(default)"
			}
			valTypeStr := regTypeString(value.Type())
			valData, err := getValueDataFast(value, f)
			if err != nil {
				log.Printf("[WARNING] read value data: file=%q key=%q value=%q err=%v", file, path, name, err)
				continue
			}

			row := []string{
				path,
				lastWrite,
				name,
				valTypeStr,
				valData,
				className,
				securityOffset,
				"0x" + strings.ToUpper(strconv.FormatUint(uint64(flags), 16)),
				strconv.Itoa(subkeyCount),
				strconv.Itoa(valueCount),
				strconv.FormatBool(hasVirtual),
			}
			rows = append(rows, row)
		}

		for _, subkey := range subkeys {
			subPath := path + `\` + subkey.Name()
			walk(subkey, subPath)
		}
	}

	walk(root, `\`)

	utils.HandleArtifactConverted(cfg, "hive", file, headers, rows, opts)
	return nil
}

func getValueDataFast(val *regparser.CM_KEY_VALUE, reader io.ReaderAt) (string, error) {
	dataLen := val.DataLength()
	inline := (dataLen & 0x80000000) != 0
	realLen := int(dataLen & 0x7fffffff)
	if realLen < 0 {
		realLen = 0
	}

	var buf []byte
	if inline {
		raw := make([]byte, 4)
		binary.LittleEndian.PutUint32(raw, val.Data())
		if realLen > len(raw) {
			realLen = len(raw)
		}
		buf = raw[:realLen]
	} else {
		off := int64(val.Data()) + 0x1000
		buf = make([]byte, realLen)
		if _, err := reader.ReadAt(buf, off); err != nil {
			return "", err
		}
	}

	switch val.Type() {
	case 1: // REG_SZ
		s := strings.TrimRight(regparser.UTF16BytesToUTF8(buf, binary.LittleEndian), "\x00")
		return s, nil

	case 2: // REG_EXPAND_SZ
		s := strings.TrimRight(regparser.UTF16BytesToUTF8(buf, binary.LittleEndian), "\x00")
		if expanded := os.ExpandEnv(s); expanded != "" {
			return expanded, nil
		}
		return s + "VNF", nil

	case 3: // REG_BINARY
		return strings.ToUpper(hex.EncodeToString(buf)), nil

	case 4: // REG_DWORD
		if len(buf) >= 4 {
			return strconv.FormatUint(uint64(binary.LittleEndian.Uint32(buf)), 10), nil
		}
		return "", nil

	case 5: // REG_DWORD_BIG_ENDIAN
		if len(buf) >= 4 {
			return strconv.FormatUint(uint64(binary.BigEndian.Uint32(buf)), 10), nil
		}
		return "", nil

	case 7: // REG_MULTI_SZ
		s := strings.TrimRight(regparser.UTF16BytesToUTF8(buf, binary.LittleEndian), "\x00")
		parts := strings.Split(s, "\x00")
		// rimuovi vuoti
		out := parts[:0]
		for _, p := range parts {
			if p != "" {
				out = append(out, p)
			}
		}
		return strings.Join(out, "|"), nil

	case 11: // REG_QWORD
		if len(buf) >= 8 {
			return strconv.FormatUint(binary.LittleEndian.Uint64(buf), 10), nil
		}
		return "", nil

	default:
		return fmt.Sprintf("Type not handled (%d): %X", val.Type(), buf), nil
	}
}

func regTypeString(typ uint32) string {
	switch typ {
	case 1:
		return "REG_SZ"
	case 2:
		return "REG_EXPAND_SZ"
	case 3:
		return "REG_BINARY"
	case 4:
		return "REG_DWORD"
	case 5:
		return "REG_DWORD_BIG_ENDIAN"
	case 6:
		return "REG_LINK"
	case 7:
		return "REG_MULTI_SZ"
	case 11:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("UNKNOWN (%d)", typ)
	}
}
