package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func CreateOutputFile(file string)*os.File {
  base := filepath.Base(file)
  fileCreated, err := os.Create("output/" + removeFileExtention(base) + ".csv")
	if err != nil {
		fmt.Printf("Error creating the csv file: %v\n", err)
		os.Exit(1)
	}
  return fileCreated
}

func removeFileExtention(file string) string {
  parts := strings.Split(file, ".")
  if len(parts) <= 1 {
    return file 
  }
  return strings.Join(parts[:len(parts)-1], ".")
}
