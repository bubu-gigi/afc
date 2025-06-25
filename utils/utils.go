package utils

import (
  "fmt"
  "os/exec"
  "strings"
)

func FindToolExe(tool string) string {
  cmd := exec.Command("where", tool)
  pathBytes, err := cmd.Output()
  if err != nil {
    fmt.Fprintf(os.Stderr, "Error finding %s path exe: %v", tool, err)
    os.Exit(1)
  }
  kapePath := strings.TrimSpace(string(pathBytes))
  fmt.Println("Found %s: %s", tool, kapePath)
  return kapePath
}

