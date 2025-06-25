package converters

import (
  "os/exec"
  "fmt"
  "afc/utils"
)

func ConvertPfToCsv(pf []string) string {
  peCmd := utils.FindToolExe("PECmd.exe")

  for _, pfPath := range pf {
    outFile := pfPath + ".csv"
    cmd := exec.Command(peCmd, "-f", pfPath, "--csv", outFile)
    output, err := cmd.CombinedOutput()
    if err != nil {
      fmt.Fprintf(os.Stderr, "Error analyzing %s: %v\n%s\n", pfPath, err, output)
    } else {
      fmt.Printf("PEcmd analyzed %s -> %s\n", pfPath, outFile)
    }
  }
}

func ConvertJumpListToCsv(jumpLists []string) {
  jlCmd := utils.FindToolExe("JLECmd.exe")

  for _, jlPath := range jumpLists {
    outFile := jlPath + ".csv"
    cmd := exec.Command(jlCmd, "-f", jlPath, "--csv", outFile)
    output, err := cmd.CombinedOutput()
    if err != nil {
      fmt.Fprintf(os.Stderr, "Error analyzing %s: %v\n%s\n", jlPath, err, output)
    } else {
      fmt.Printf("JLECmd analyzed %s -> %s\n", jlPath, outFile)
    }
  }
}

func ConvertJumpListToCsv(jumpLists []string) {
  jlCmd := utils.FindToolExe("JLECmd.exe")

  for _, jlPath := range jumpLists {
    outFile := jlPath + ".csv"
    cmd := exec.Command(jlCmd, "-f", jlPath, "--csv", outFile)
    output, err := cmd.CombinedOutput()
    if err != nil {
      fmt.Fprintf(os.Stderr, "Error analyzing %s: %v\n%s\n", jlPath, err, output)
    } else {
      fmt.Printf("JLECmd analyzed %s -> %s\n", jlPath, outFile)
    }
  }
}

func ConvertLnkFilesToCsv(lnkFiles []string) {
  leCmd := utils.FindToolExe("LECmd.exe")

  for _, lnkPath := range lnkFiles {
    outFile := lnkPath + ".csv"
    cmd := exec.Command(leCmd, "-f", lnkPath, "--csv", outFile)
    output, err := cmd.CombinedOutput()
    if err != nil {
      fmt.Fprintf(os.Stderr, "Error analyzing %s: %v\n%s\n", lnkPath, err, output)
    } else {
      fmt.Printf("LECmd analyzed %s -> %s\n", lnkPath, outFile)
    }
  }
}

func ConvertWindowsTimelineToCsv(timelineFiles []string) {
  wxtCmd := utils.FindToolExe("WxTCmd.exe")

  for _, timelinePath := range timelineFiles {
    outFile := timelinePath + ".csv"
    cmd := exec.Command(wxtCmd, "-f", timelinePath, "--csv", outFile)
    output, err := cmd.CombinedOutput()
    if err != nil {
      fmt.Fprintf(os.Stderr, "Error analyzing %s: %v\n%s\n", timelinePath, err, output)
    } else {
      fmt.Printf("WxTCmd analyzed %s -> %s\n", timelinePath, outFile)
    }
  }
}

func ConvertWindowsTimelineToCsv(timelineFiles []string) {
  wxtCmd := utils.FindToolExe("WxTCmd.exe")

  for _, timelinePath := range timelineFiles {
    outFile := timelinePath + ".csv"
    cmd := exec.Command(wxtCmd, "-f", timelinePath, "--csv", outFile)
    output, err := cmd.CombinedOutput()
    if err != nil {
      fmt.Fprintf(os.Stderr, "Error analyzing %s: %v\n%s\n", timelinePath, err, output)
    } else {
      fmt.Printf("WxTCmd analyzed %s -> %s\n", timelinePath, outFile)
    }
  }
}

func ConvertRecycleBinToCsv(recycleBin []string) {
  rbCmd := utils.FindToolExe("RBCmd.exe")

  for _, rbPath := range recycleBin {
    outFile := rbPath + ".csv"
    cmd := exec.Command(rbCmd, "-f", rbPath, "--csv", outFile)
    output, err := cmd.CombinedOutput()
    if err != nil {
      fmt.Fprintf(os.Stderr, "Error analyzing %s: %v\n%s\n", rbPath, err, output)
    } else {
      fmt.Printf("RBCmd analyzed %s -> %s\n", rbPath, outFile)
    }
  }
}

func ConvertSrumToCsv(srumFiles []string) {
  srumCmd := utils.FindToolExe("SRUMECmd.exe")

  for _, srumPath := range srumFiles {
    outFile := srumPath + ".csv"
    cmd := exec.Command(srumCmd, "-f", srumPath, "--csv", outFile)
    output, err := cmd.CombinedOutput()
    if err != nil {
      fmt.Fprintf(os.Stderr, "Error analyzing %s: %v\n%s\n", srumPath, err, output)
    } else {
      fmt.Printf("SRUMECmd analyzed %s -> %s\n", srumPath, outFile)
    }
  }
}

func ConvertAmcacheToCsv(amcacheFiles []string) {
  amcacheCmd := utils.FindToolExe("AmcacheParser.exe")

  for _, amPath := range amcacheFiles {
    outFile := amPath + ".csv"
    cmd := exec.Command(amcacheCmd, "-f", amPath, "--csv", outFile)
    output, err := cmd.CombinedOutput()
    if err != nil {
      fmt.Fprintf(os.Stderr, "Error analyzing %s: %v\n%s\n", amPath, err, output)
    } else {
      fmt.Printf("AmcacheParser analyzed %s -> %s\n", amPath, outFile)
    }
  }
}

func ConvertAmcacheToCsv(amcacheFiles []string) {
  amcacheCmd := utils.FindToolExe("AmcacheParser.exe")

  for _, amPath := range amcacheFiles {
    outFile := amPath + ".csv"
    cmd := exec.Command(amcacheCmd, "-f", amPath, "--csv", outFile)
    output, err := cmd.CombinedOutput()
    if err != nil {
      fmt.Fprintf(os.Stderr, "Error analyzing %s: %v\n%s\n", amPath, err, output)
    } else {
      fmt.Printf("AmcacheParser analyzed %s -> %s\n", amPath, outFile)
    }
  }
}
