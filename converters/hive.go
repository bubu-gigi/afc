package converters

import (
	"afc/config"
	utils "afc/lib"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	regparser "www.velocidex.com/golang/regparser"
)

func ConvertRegistryHiveToCsv(files []string, cfg *config.Config) {
	for _, file := range files {
		if err := convertHive(file, cfg); err != nil {
			log.Printf("hive|Error processing file %s: %v", file, err)
		}
	}
}

func convertHive(file string, cfg *config.Config) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("hive|error opening file: %w", err)
	}
	defer f.Close()

	registry, err := regparser.NewRegistry(f)
	if err != nil {
		return fmt.Errorf("hive|error parsing hive: %w", err)
	}

	root := registry.OpenKey("")
	if root == nil {
		return fmt.Errorf("hive|root key not found")
	}

	headers := []string{"Path", "LastWrite", "Name", "Type", "Value"}
	var rows [][]string
	visited := make(map[string]bool)

	var walk func(*regparser.CM_KEY_NODE, string)
	walk = func(key *regparser.CM_KEY_NODE, path string) {
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
			valData, err := getValueData(value, f)
			if err != nil {
				log.Printf("hive|Error reading data in file %s (key: %s.%s): %v", file, path, name, err)
				continue
			}
			rows = append(rows, []string{
				path,
				lastWrite,
				name,
				valType,
				valData,
			})
		}

		for _, subkey := range key.Subkeys() {
			subPath := path + `\` + subkey.Name()
			walk(subkey, subPath)
		}
	}

	walk(root, `\`)

	if err := utils.SendCsvToWazuh(cfg, headers, rows); err != nil {
		return fmt.Errorf("hive|error sending to Wazuh: %w", err)
	}

	return nil
}

func getValueData(val *regparser.CM_KEY_VALUE, reader io.ReaderAt) (string, error) {
	dataOffset := int64(val.Data())
	dataLength := val.DataLength()
	dataType := val.Type()

	buf := make([]byte, dataLength)
	_, err := reader.ReadAt(buf, dataOffset+0x1000)
	if err != nil {
		return "", err
	}

	switch dataType {
	case 1:
		return regparser.UTF16BytesToUTF8(buf, binary.LittleEndian), nil
	case 2:
		val := regparser.UTF16BytesToUTF8(buf, binary.LittleEndian)
		expanded := os.ExpandEnv(val)
		if expanded == "" {
			return val + "VNF", nil
		}
		return expanded, nil
	case 3:
		return strings.ToUpper(fmt.Sprintf("%X", buf)), nil
	case 4:
		if len(buf) >= 4 {
			return fmt.Sprintf("%d", binary.LittleEndian.Uint32(buf)), nil
		}
	case 11:
		if len(buf) >= 8 {
			return fmt.Sprintf("%d", binary.LittleEndian.Uint64(buf)), nil
		}
	case 7:
		str := regparser.UTF16BytesToUTF8(buf, binary.LittleEndian)
		return strings.Join(strings.Split(str, "\x00"), "|"), nil
	default:
		return fmt.Sprintf("Type not handled (%d): %X", dataType, buf), nil
	}
	return "", nil
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
