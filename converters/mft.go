package converters

import (
	utils "afc/lib"
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"www.velocidex.com/golang/go-ntfs/parser"
)

func ConvertMFTToCsv(files []string) {
	for _, file := range files {
		convertMFT(file)
	}
}

func convertMFT(file string) {
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("Errore apertura file: %v\n", err)
		return
	}
	defer f.Close()

	stat, _ := f.Stat()
	size := stat.Size()

	outFile := utils.CreateOutputFile(file)
	defer outFile.Close()
	writer := csv.NewWriter(outFile)
	defer writer.Flush()

	// Header
	writer.Write([]string{
		"EntryNumber", "SequenceNumber", "InUse",
		"ParentEntryNumber", "ParentSequenceNumber", "ParentPath",
		"FileName", "Extension", "FileSize", "ReferenceCount",
		"IsDirectory", "HasAds", "IsAds", "SI<FN", "uSecZeros",
		"Copied", "SIFlags", "NameType",
		"Created0x10", "Created0x30", "LastModified0x10", "LastModified0x30",
		"LastRecordChange0x10", "LastRecordChange0x30",
		"LastAccess0x10", "LastAccess0x30",
		"LogfileSequenceNumber",
	})

	ctx := context.Background()
	stream := parser.ParseMFTFile(ctx, f, size, 4096, 1024)

	for row := range stream {
		if row == nil {
			continue
		}

		fileName := ""
		nameType := ""
		if len(row.FileNames) > 0 {
			fileName = row.FileNames[len(row.FileNames)-1]
		}
		nameType = row.FileNameTypes()

		isAds := strings.Contains(fileName, ":") && !row.IsDir
		extension := filepath.Ext(fileName)

		writer.Write([]string{
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
		})
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
