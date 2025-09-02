package utils

import (
	"afc/config"
	"afc/flags"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

const windowsToUnixOffset = 116444736000000000	

func FileTimeToString(ft uint64) string {
	if ft == 0 {
    	return ""
	}
	if ft < windowsToUnixOffset {
		return "Invalid FILETIME"
	}
	unixNano := (ft - windowsToUnixOffset) * 100
	t := time.Unix(0, int64(unixNano)).UTC()
	return t.Format("2006-01-02 15:04:05.0000000")
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

func FormatGUID(b []byte) string {
	if len(b) != 16 {
		return "INVALID_GUID"
	}

	d1 := binary.LittleEndian.Uint32(b[0:4])
	d2 := binary.LittleEndian.Uint16(b[4:6])
	d3 := binary.LittleEndian.Uint16(b[6:8])
	d4 := b[8:10]
	d5 := b[10:16]

	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		d1, d2, d3,
		d4[0], d4[1],
		d5[0], d5[1], d5[2], d5[3], d5[4], d5[5],
	)
}

func IsRegistryHive(path string) bool {
	filename := strings.ToLower(filepath.Base(path))

	switch filename {
	case "sam", "software", "security", "system":
		return true
	default:
		return strings.Contains(filename, "ntuser.dat")
	}
}

func ShouldProcessArtifact(name string) bool {
	for _, f := range flags.ArtifactFilter {
		if f == "all" || strings.EqualFold(f, name) {
			return true
		}
	}
	return false
}

func SaveCsvToDisk(cfg *config.Config, artifactSubdir string, srcFilename string, headers []string, rows [][]string) (string, error) {
	outRoot := "./out"
	if cfg != nil {
		type hasPaths struct {
			Paths struct {
				Output string
			}
		}
		if cfgTyped, ok := any(cfg).(*hasPaths); ok && cfgTyped.Paths.Output != "" {
			outRoot = cfgTyped.Paths.Output
		}
	}

	outDir := filepath.Join(outRoot, artifactSubdir)

	base := strings.TrimSuffix(filepath.Base(srcFilename), filepath.Ext(srcFilename)) + ".csv"
	outPath := filepath.Join(outDir, base)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", fmt.Errorf("cannot create output dir %s: %w", outDir, err)
	}

	f, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("cannot create CSV file %s: %w", outPath, err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if len(headers) > 0 {
		if err := w.Write(headers); err != nil {
			return "", fmt.Errorf("cannot write CSV header to %s: %w", outPath, err)
		}
	}
	for _, r := range rows {
		if err := w.Write(r); err != nil {
			return "", fmt.Errorf("cannot write CSV row to %s: %w", outPath, err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return "", fmt.Errorf("csv writer error for %s: %w", outPath, err)
	}
	return outPath, nil
}

func HandleArtifactConverted(cfg *config.Config, artifactName string, file string, headers []string, rows [][]string, opts *flags.GlobalOptions) {
	if opts.SkipWazuhSend {
    	out, err := SaveCsvToDisk(cfg, artifactName, file, headers, rows)
		if err != nil {
			log.Printf("failed to save %s CSV: %s", artifactName, err)
		}
		log.Printf("[INFO] CSV saved to %s (records: %d)", out, len(rows))
	} else {
		if err := SendToWazuh(cfg, file, headers, rows, opts.DumpRequestBodies); err != nil {
			log.Printf("failed to send %s to Wazuh: %s", artifactName, err)
		}
		log.Printf("[INFO] Converted %s %s with %d records", artifactName, file, len(rows))
	}
}