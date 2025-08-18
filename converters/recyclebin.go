package converters

import (
	"afc/config"
	"afc/flags"
	utils "afc/lib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

func ConvertRecycleBinToCsv(files []string, config *config.Config, opts *flags.GlobalOptions) {
	for _, file := range files {
		switch {
		case strings.HasPrefix(filepath.Base(file), "$I"):
			entry, err := ParseDollarI(file)
			if err != nil {
				log.Printf("recyclebin: error parsing $I file %s: %v", file, err)
				continue
			}
			if err := sendDollarIToWazuh(file, entry, config); err != nil {
				log.Printf("recyclebin: error sending $I file %s to Wazuh: %v", file, err)
			}

		case strings.EqualFold(filepath.Base(file), "INFO2"):
			entries, err := ParseINFO2(file)
			if err != nil {
				log.Printf("recyclebin: error parsing INFO2 file %s: %v", file, err)
				continue
			}
			if err := sendINFO2ToWazuh(file, entries, config); err != nil {
				log.Printf("recyclebin: error sending INFO2 file %s to Wazuh: %v", file, err)
			}
		}
	}
}

func sendDollarIToWazuh(file string, entry RecycleEntry, config *config.Config) error {
	headers := []string{"Version", "FileSize", "DeletedTime", "OriginalPath", "SourceFile", "ParsedAt"}
	row := []string{
		fmt.Sprintf("%d", entry.Version),
		fmt.Sprintf("%d", entry.FileSize),
		entry.DeletedTime.Format(time.RFC3339),
		entry.OriginalPath,
		file,
		time.Now().Format(time.RFC3339),
	}
	return utils.SendCsvToWazuh(config, headers, [][]string{row})
}

func sendINFO2ToWazuh(file string, entries []Info2Entry, config *config.Config) error {
	headers := []string{
		"FileIndex", "DriveNumber", "FileNameASCII", "FileNameUTF16", "DeletedTime", "FileSize", "SourceFile", "ParsedAt",
	}
	var rows [][]string
	for _, e := range entries {
		row := []string{
			fmt.Sprintf("%d", e.FileIndex),
			fmt.Sprintf("%d", e.DriveNumber),
			e.FileNameASCII,
			e.FileNameUTF16,
			e.DeletedTime.Format(time.RFC3339),
			fmt.Sprintf("%d", e.FileSize),
			file,
			time.Now().Format(time.RFC3339),
		}
		rows = append(rows, row)
	}
	return utils.SendCsvToWazuh(config, headers, rows)
}

func ParseDollarI(path string) (RecycleEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return RecycleEntry{}, err
	}
	defer f.Close()

	var version, fileSize, deletedRaw uint64
	if err := binary.Read(f, binary.LittleEndian, &version); err != nil {
		return RecycleEntry{}, err
	}
	if version != 1 && version != 2 {
		return RecycleEntry{}, fmt.Errorf("unsupported $I version: %d", version)
	}
	if err := binary.Read(f, binary.LittleEndian, &fileSize); err != nil {
		return RecycleEntry{}, err
	}
	if err := binary.Read(f, binary.LittleEndian, &deletedRaw); err != nil {
		return RecycleEntry{}, err
	}

	deletedTime := time.Unix(0, int64(deletedRaw-116444736000000000)*100)

	utf16Bytes, err := io.ReadAll(f)
	if err != nil {
		return RecycleEntry{}, err
	}

	u16 := make([]uint16, 0, len(utf16Bytes)/2)
	for i := 0; i+1 < len(utf16Bytes); i += 2 {
		val := binary.LittleEndian.Uint16(utf16Bytes[i : i+2])
		if val == 0 {
			break
		}
		u16 = append(u16, val)
	}
	originalPath := strings.TrimRight(string(utf16.Decode(u16)), "\x00")

	return RecycleEntry{
		Version:      version,
		FileSize:     fileSize,
		DeletedTime:  deletedTime,
		OriginalPath: originalPath,
	}, nil
}

func ParseINFO2(path string) ([]Info2Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	header := make([]byte, 16)
	if _, err := f.Read(header); err != nil {
		return nil, err
	}

	entrySize := binary.LittleEndian.Uint32(header[12:16])
	if entrySize != 280 {
		return nil, errors.New("unsupported INFO2 format")
	}

	var entries []Info2Entry
	for {
		record := make([]byte, 280)
		n, err := f.Read(record)
		if err != nil || n < 280 {
			break
		}

		index := int32(binary.LittleEndian.Uint32(record[0:4]))
		drive := record[4]
		nameASCII := strings.TrimRight(string(record[8:264]), "\x00")
		timestamp := int64(binary.LittleEndian.Uint32(record[264:268]))
		delTime := time.Unix(timestamp, 0).UTC()
		size := binary.LittleEndian.Uint32(record[268:272])

		u16 := make([]uint16, 0, 4)
		for i := 272; i+1 < 280; i += 2 {
			u := binary.LittleEndian.Uint16(record[i : i+2])
			if u == 0 {
				break
			}
			u16 = append(u16, u)
		}
		nameUTF16 := strings.TrimRight(string(utf16.Decode(u16)), "\x00")

		entries = append(entries, Info2Entry{
			FileIndex:     index,
			DriveNumber:   drive,
			FileNameASCII: nameASCII,
			FileNameUTF16: nameUTF16,
			DeletedTime:   delTime,
			FileSize:      size,
		})
	}

	return entries, nil
}
