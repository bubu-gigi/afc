package converters

import (
	"afc/config"
	"afc/flags"
	utils "afc/lib"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
	"unicode/utf16"
)

func ConvertUsnJrnlToCsv(files []string, config *config.Config, opts *flags.GlobalOptions) {
	for _, file := range files {
		if err := convertUsnJrnl(file, config, opts); err != nil {
			log.Printf("usn: failed to convert file %s: %v", file, err)
		}
	}
}

func convertUsnJrnl(file string, config *config.Config, opts *flags.GlobalOptions) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("open error: %w", err)
	}
	defer f.Close()

	var rows [][]string
	for {
		rec, err := parseUsnRecord(f)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			log.Printf("usn: record parse error in %s: %v", file, err)
			continue
		}

		row := []string{
			fmt.Sprint(rec.RecordLength),
			fmt.Sprint(rec.MajorVersion),
			fmt.Sprint(rec.MinorVersion),
			fmt.Sprintf("%d", rec.FileReferenceNumber),
			fmt.Sprintf("%d", rec.ParentFileReferenceNum),
			fmt.Sprintf("%d", rec.Usn),
			rec.Timestamp.Format(time.RFC3339),
			fmt.Sprintf("0x%X", rec.Reason),
			strings.Join(decodeReasonFlags(rec.Reason), "|"),
			fmt.Sprintf("0x%X", rec.SourceInfo),
			fmt.Sprintf("%d", rec.SecurityID),
			fmt.Sprintf("%d", rec.FileAttributes),
			fmt.Sprintf("0x%X", rec.FileAttributes),
			rec.FileName,
		}
		rows = append(rows, row)
	}

	if len(rows) == 0 {
		log.Printf("usn: no valid records found in %s", file)
		return nil
	}

	headers := []string{
		"RecordLength", "MajorVersion", "MinorVersion",
		"FileReferenceNumber", "ParentFileReferenceNumber", "USN",
		"Timestamp", "Reason", "ReasonDecoded", "SourceInfo",
		"SecurityID", "FileAttributes", "FileAttributesHex", "FileName",
	}

	utils.HandleArtifactConverted(config, "journal", file, headers, rows, opts)


	return nil
}

func parseUsnRecord(r io.Reader) (*UsnRecord, error) {
	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, err
	}

	buf := make([]byte, length-4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	full := append(make([]byte, 4), buf...)
	binary.LittleEndian.PutUint32(full[:4], length)

	if len(full) < 60 {
		return nil, fmt.Errorf("invalid record length")
	}

	record := UsnRecord{}
	record.RecordLength = length
	record.MajorVersion = binary.LittleEndian.Uint16(full[4:6])
	record.MinorVersion = binary.LittleEndian.Uint16(full[6:8])

	if record.MajorVersion != 2 || record.MinorVersion != 0 {
		return nil, fmt.Errorf("unsupported USN record version: %d.%d", record.MajorVersion, record.MinorVersion)
	}

	record.FileReferenceNumber = binary.LittleEndian.Uint64(full[8:16])
	record.ParentFileReferenceNum = binary.LittleEndian.Uint64(full[16:24])
	record.Usn = binary.LittleEndian.Uint64(full[24:32])
	rawTime := binary.LittleEndian.Uint64(full[32:40])
	record.Timestamp = time.Unix(0, int64(rawTime-116444736000000000)*100)
	record.Reason = binary.LittleEndian.Uint32(full[40:44])
	record.SourceInfo = binary.LittleEndian.Uint32(full[44:48])
	record.SecurityID = binary.LittleEndian.Uint32(full[48:52])
	record.FileAttributes = binary.LittleEndian.Uint32(full[52:56])
	nameLen := binary.LittleEndian.Uint16(full[56:58])
	nameOffset := binary.LittleEndian.Uint16(full[58:60])

	if int(nameOffset)+int(nameLen) > len(full) {
		return nil, fmt.Errorf("invalid name offset/length")
	}

	nameBytes := full[nameOffset : nameOffset+nameLen]
	utf16Chars := make([]uint16, nameLen/2)
	for i := 0; i < len(utf16Chars); i++ {
		utf16Chars[i] = binary.LittleEndian.Uint16(nameBytes[i*2 : i*2+2])
	}
	record.FileName = string(utf16.Decode(utf16Chars))

	return &record, nil
}

func decodeReasonFlags(reason uint32) []string {
	var flags []string
	for val, name := range ReasonFlags {
		if reason&val != 0 {
			flags = append(flags, name)
		}
	}
	return flags
}
