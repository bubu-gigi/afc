package converters

import (
	utils "afc/lib"
	"context"
	"encoding/csv"
	"fmt"
	"os"

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
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		fmt.Printf("Error getting file size: %v\n", err)
		os.Exit(1)
	}
	size := stat.Size()

	fileOut := utils.CreateOutputFile(file)
	defer fileOut.Close()

	writer := csv.NewWriter(fileOut)
	defer writer.Flush()

	// Header
	writer.Write([]string{"Inode", "FullPath", "FileName", "Size", "IsDir"})

	ctx := context.Background()
	stream := parser.ParseMFTFile(ctx, f, size, 4096, 1024)

	for row := range stream {
		err := writer.Write([]string{
			fmt.Sprintf("%d", row.EntryNumber),
			row.FullPath(),
			row.FileName(),
			fmt.Sprintf("%d", row.FileSize),
			fmt.Sprintf("%v", row.IsDir),
		})
		if err != nil {
			fmt.Printf("Error writing row: %v\n", err)
		}
	}
}
