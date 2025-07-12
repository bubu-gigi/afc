package converters

import (
	utils "afc/lib"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf16"
)

func ConvertUsnJrnlToCsv(files []string) {
	for _, file := range files {
		convertUsnJrnl(file)
	}
}

func convertUsnJrnl(file string) {
	f, err := os.Open(file)
	if err != nil {
		fmt.Println("Error opening the file")
		return
	}
	defer f.Close()

	var records []*UsnRecord
	for {
		rec, err := parseUsnRecord(f)
		if err == io.EOF {
			break
		} else if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			fmt.Println("Error reading record:", err)
			continue
		}
		records = append(records, rec)
	}
	fileOut := utils.CreateOutputFile(file)
	defer fileOut.Close()


	w := csv.NewWriter(fileOut)
	defer w.Flush()

	w.Write([]string{"Time", "USN", "Filename", "Reasons", "Attributes"})
	for _, r := range records {
		w.Write([]string{
			r.Timestamp.Format(time.RFC3339),
			fmt.Sprintf("%d", r.Usn),
			r.FileName,
			strings.Join(decodeReasonFlags(r.Reason), "|"),
			fmt.Sprintf("0x%X", r.FileAttributes),
		})
	}
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
