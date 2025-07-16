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

	"github.com/richardlehane/mscfb"
)

func ConvertJumpToCsv(files []string, config *config.Config) {
	for _, file := range files {
		if strings.HasSuffix(file, ".automaticDestinations-ms") {
			if err := convertAutomaticDestination(file, config); err != nil {
				log.Printf("[ERROR] Failed to convert jump list file %s: %v", file, err)
			}
		}
	}
}

func convertAutomaticDestination(file string, config *config.Config) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("cannot open jump list file %s: %w", file, err)
	}
	defer f.Close()

	rdr, err := mscfb.New(f)
	if err != nil {
		return fmt.Errorf("invalid CFB file %s: %w", file, err)
	}

	for entry, err := rdr.Next(); err == nil; entry, err = rdr.Next() {
		if entry.Name == "DestList" {
			destEntries := parseDestList(rdr)
			if destEntries != nil {
				exportDestListToCsv(file, destEntries, config)
			}
			break
		}
	}

	log.Printf("[INFO] Processed jump list file %s", file)
	return nil
}

func parseDestList(r io.Reader) []map[string]string {
	var entries []map[string]string
	header := make([]byte, 32)
	if _, err := io.ReadFull(r, header); err != nil {
		log.Printf("[WARNING] Failed to read DestList header: %v", err)
		return nil
	}

	for {
		entry := make([]byte, 114)
		_, err := io.ReadFull(r, entry)
		if err != nil {
			break
		}

		creationTime := binary.LittleEndian.Uint64(entry[8:16])
		lastAccessTime := binary.LittleEndian.Uint64(entry[16:24])
		pathHash := binary.LittleEndian.Uint64(entry[28:36])
		droidVolumeID := utils.FormatGUID(entry[36:52])
		droidFileID := utils.FormatGUID(entry[52:68])
		birthDroidVolumeID := utils.FormatGUID(entry[68:84])
		birthDroidFileID := utils.FormatGUID(entry[84:100])

		entries = append(entries, map[string]string{
			"CreationTime":       utils.FileTimeToString(creationTime),
			"LastAccessTime":     utils.FileTimeToString(lastAccessTime),
			"PathHash":           fmt.Sprintf("0x%016X", pathHash),
			"DroidVolumeID":      droidVolumeID,
			"DroidFileID":        droidFileID,
			"BirthDroidVolumeID": birthDroidVolumeID,
			"BirthDroidFileID":   birthDroidFileID,
		})
	}

	return entries
}

func exportDestListToCsv(source string, entries []map[string]string, config *config.Config) {
	headers := []string{
		"CreationTime", "LastAccessTime", "PathHash",
		"DroidVolumeID", "DroidFileID", "BirthDroidVolumeID", "BirthDroidFileID",
	}

	var rows [][]string
	for _, e := range entries {
		rows = append(rows, []string{
			e["CreationTime"],
			e["LastAccessTime"],
			e["PathHash"],
			e["DroidVolumeID"],
			e["DroidFileID"],
			e["BirthDroidVolumeID"],
			e["BirthDroidFileID"],
		})
	}

	if err := utils.SendCsvToWazuh(config, headers, rows); err != nil {
		log.Printf("[ERROR] Failed to send DestList CSV for %s: %v", source, err)
	} else {
		log.Printf("[INFO] Sent DestList CSV for %s with %d records", source, len(rows))
	}
}












