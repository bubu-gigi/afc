package converters

import (
	"afc/config"
	utils "afc/lib"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"www.velocidex.com/golang/go-ntfs/parser"
)

func ConvertMFTToCsv(files []string, config *config.Config) {
	for _, file := range files {
		if err := convertMFT(file, config); err != nil {
			log.Printf("mft: failed to convert file %s: %v", file, err)
		}
	}
}

func convertMFT(file string, config *config.Config) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("open error: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat error: %w", err)
	}
	size := stat.Size()

	headers := []string{
		"EntryNumber", "SequenceNumber", "InUse",
		"ParentEntryNumber", "ParentSequenceNumber", "ParentPath",
		"FileName", "Extension", "FileSize", "ReferenceCount",
		"IsDirectory", "HasAds", "IsAds", "SI<FN", "uSecZeros",
		"Copied", "SIFlags", "NameType",
		"Created0x10", "Created0x30", "LastModified0x10", "LastModified0x30",
		"LastRecordChange0x10", "LastRecordChange0x30",
		"LastAccess0x10", "LastAccess0x30",
		"LogfileSequenceNumber",
		"Components", "AllFileNames", "Links",
	}

	var rows [][]string
	ctx := context.Background()
	stream := parser.ParseMFTFile(ctx, f, size, 4096, 1024)

	for row := range stream {
		if row == nil {
			continue
		}

		fileName := ""
		if len(row.FileNames) > 0 {
			fileName = row.FileNames[len(row.FileNames)-1]
		}

		nameType := row.FileNameTypes()
		isAds := strings.Contains(fileName, ":") && !row.IsDir
		extension := filepath.Ext(fileName)

		rows = append(rows, []string{
			fmt.Sprintf("%d", row.EntryNumber),
			fmt.Sprintf("%d", row.SequenceNumber),
			fmt.Sprintf("%v", row.InUse),
			fmt.Sprintf("%d", row.ParentEntryNumber),
			fmt.Sprintf("%d", row.ParentSequenceNumber),
			filepath.Dir(row.FullPath()),
			fileName,
			extension,
			fmt.Sprintf("%d", row.FileSize),
			fmt.Sprintf("%d", row.ReferenceCount),
			fmt.Sprintf("%v", row.IsDir),
			fmt.Sprintf("%v", row.HasADS),
			fmt.Sprintf("%v", isAds),
			fmt.Sprintf("%v", row.SI_Lt_FN),
			fmt.Sprintf("%v", row.USecZeros),
			fmt.Sprintf("%v", row.Copied),
			row.SIFlags,
			nameType,
			formatTime(row.Created0x10),
			formatTime(row.Created0x30),
			formatTime(row.LastModified0x10),
			formatTime(row.LastModified0x30),
			formatTime(row.LastRecordChange0x10),
			formatTime(row.LastRecordChange0x30),
			formatTime(row.LastAccess0x10),
			formatTime(row.LastAccess0x30),
			fmt.Sprintf("%d", row.LogFileSeqNum),
			strings.Join(row.Components(), "\\"),
			strings.Join(row.FileNames, "|"),
			strings.Join(row.Links(), "||"),
		})
	}

	if len(rows) == 0 {
		log.Printf("mft: no rows to send for file %s", file)
		return nil
	}

	if err := utils.SendCsvToWazuh(config, headers, rows); err != nil {
		return fmt.Errorf("send to Wazuh failed: %w", err)
	}

	return nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
