package main

import (
  "os"
  "os/exec"
  "strings"
  "fmt"
  "flag"
  "path/filepath"
  "afc/utils"
  "afc/converters"
)

func main() {
  kpath, ksource, kdest := handleArguments()

  cmd := exec.Command(
    kpath,
    "--tsource", ksource,
    "--tdest", kdest,
    "--target", "KapeTriage",
    "--v",
  )

  output, err := cmd.CombinedOutput()
  if err != nil {
    fmt.Fprintf(os.Stderr, "Error running KAPE:\n%s\nOutput:\n%s\n", err, output)
    fmt.Printf("Please check whether is into the PATH")
    os.Exit(1)
  }

  fmt.Println("Kape run successfully")

  pf, jl, registry, evtx, _, _, _, _, _, _, jobs, _,
  lnk, recycle, usnjrnl, timeline, _, _, _, _, _, thumb,
  srum, _, amcache, _, _, mft := collectArtifacts(kdest)

  converters.ConvertPfToCsv(pf)
  fmt.Println("Converted prefetch to csv successfully")

  converters.ConvertJumpListToCsv(jl)
  fmt.Println("Converted jump list to csv successfully")

  converters.ConvertRegistryToCsv(registry)
  fmt.Println("Converted registry hives to csv successfully")

  converters.ConvertEventLogsToCsv(evtx)
  fmt.Println("Converted evtx to csv successfully")

  converters.ConvertLnkFilesToCsv(lnk)
  fmt.Println("Converted link to csv successfully")

  converters.ConvertWindowsTimelineToCsv(timeline)
  fmt.Println("Converted windows timeline to csv successfully")

  converters.ConvertRecycleBinToCsv(recycle)
  fmt.Println("Converted recycle bin to csv successfully")

  converters.ConvertSrumToCsv(srum)
  fmt.Println("Converted srum to csv successfully")

  converters.ConvertScheduledTasksToCsv(jobs)
  fmt.Println("Converted scheduled tasks to csv successfully")

  converters.ConvertAmcacheToCsv(amcache)
  fmt.Println("Converted amcache to csv successfully")

  converters.ConvertMftToCsv(mft)
  fmt.Println("Converted mft to csv successfully")

  converters.ConvertThumbcacheToCsv(thumb)
  fmt.Println("Converted thumb to csv successfully")

  converters.ConvertUsnJrnlToCsv(usnjrnl)
  fmt.Println("Converted usnjrnl to csv successfully")
}

func handleArguments() (string, string, string) {
  kpath := flag.String("kpath", utils.FindToolExe("kape.exe"), "Kape Directory")
  ksource := flag.String("ksource", "C:\\" ,"KapeTriage source")
  kdest := flag.String("kdest", "C:\\Output", "KapeTriage destination")
  flag.Parse()

  if *ksource == "" || *kdest == "" {
    fmt.Printf("Error: ksource and kdest must be specified\n")
    os.Exit(1)
  }
  return *kpath, *ksource, *kdest
}

func isRegistryHive(path string) bool {
  return strings.Contains(strings.ToLower(filepath.Base(path)), "sam") ||
    strings.Contains(strings.ToLower(filepath.Base(path)), "software") ||
    strings.Contains(strings.ToLower(filepath.Base(path)), "security") ||
    strings.Contains(strings.ToLower(filepath.Base(path)), "system") ||
    strings.Contains(strings.ToLower(filepath.Base(path)), "ntuser.dat")
}

func collectArtifacts(kdest string) ([]string, []string, []string, []string, []string, []string, []string, []string, []string, []string, []string, []string,
  []string, []string, []string, []string, []string, []string, []string, []string, []string, []string, []string, []string, []string, []string, []string, []string) {
  prefetch := []string{}
  jumpList := []string{}
  registry := []string{}
  eventLogs := []string{}
  pageFiles := []string{} // https://github.com/volatilityfoundation/volatility , https://github.com/simsong/bulk_extractor
  hiberFiles := []string{} // HiberfilConverter.exe
  memoryDumps := []string{} // volatility
  powershellHistory := []string{} // easy csv as Line,Command or not(?)
  browserCache := []string{} // TODO?
  browserHistory := []string{} // TODO?
  scheduledTasks := []string{}
  hostsFiles := []string{} // as linux, is needed a csv for that?
  lnkFiles := []string{}
  recycleBin := []string{}
  usnJrnl := []string{}
  windowsTimeline := []string{}
  scheduledTaskXMLs := []string{} // how's the best wat to parse that? They are xml so we can do as we want
  werFiles := []string{} // same for this, custom convertor?
  thumbcache := []string{}
  bitsJobs := []string{}
  recentLnkFiles := []string{}
  rdpCache := []string{}
  srumFiles := []string{}
  wmiActivity := []string{}
  amcache := []string{}
  defenderLogs := []string{}
  eventTrace := []string{}
  mftFiles := []string{}

  filepath.Walk(kdest, func(path string, info os.FileInfo, err error) error {
    if err != nil {
      return err
    }

    lowerPath := strings.ToLower(path)

    switch {
    case strings.HasSuffix(lowerPath, ".pf"):
      prefetch = append(prefetch, path)

    case isRegistryHive(path):
      registry = append(registry, path)

    case strings.HasSuffix(lowerPath, ".evtx"):
      eventLogs = append(eventLogs, path)

    case strings.Contains(lowerPath, "pagefile.sys"):
      pageFiles = append(pageFiles, path)

    case strings.HasSuffix(lowerPath, ".automaticdestinations-ms"), strings.HasSuffix(lowerPath, ".customdestinations-ms"):
      jumpList = append(jumpList, path)

    case strings.Contains(lowerPath, "hiberfil.sys"):
      hiberFiles = append(hiberFiles, path)

    case strings.HasSuffix(lowerPath, ".dmp"):
      memoryDumps = append(memoryDumps, path)

    case strings.HasPrefix(filepath.Base(lowerPath), "consolehost_history.txt"):
      powershellHistory = append(powershellHistory, path)

    case filepath.Base(lowerPath) == "webcachev01.dat":
      browserCache = append(browserCache, path)

    case filepath.Base(lowerPath) == "history" || strings.HasSuffix(lowerPath, ".sqlite"):
      browserHistory = append(browserHistory, path)

    case strings.HasSuffix(lowerPath, ".job"):
      scheduledTasks = append(scheduledTasks, path)

    case filepath.Base(lowerPath) == "hosts":
      hostsFiles = append(hostsFiles, path)

    case strings.HasSuffix(lowerPath, ".lnk"):
      lnkFiles = append(lnkFiles, path)

    case strings.Contains(lowerPath, "$recycle.bin"):
      recycleBin = append(recycleBin, path)

    case strings.Contains(lowerPath, "$usnjrnl"):
      usnJrnl = append(usnJrnl, path)

    case filepath.Base(lowerPath) == "activitiescache.db":
      windowsTimeline = append(windowsTimeline, path)

    case strings.HasSuffix(lowerPath, ".xml") && strings.Contains(lowerPath, "windows\\system32\\tasks"):
      scheduledTaskXMLs = append(scheduledTaskXMLs, path)

    case strings.HasSuffix(lowerPath, ".wer"):
      werFiles = append(werFiles, path)

    case strings.HasPrefix(filepath.Base(lowerPath), "thumbcache_") && strings.HasSuffix(lowerPath, ".db"):
      thumbcache = append(thumbcache, path)

    case strings.HasPrefix(filepath.Base(lowerPath), "qmgr") && strings.HasSuffix(lowerPath, ".dat"):
      bitsJobs = append(bitsJobs, path)

    case strings.Contains(lowerPath, "\\recent\\") && strings.HasSuffix(lowerPath, ".lnk"):
      recentLnkFiles = append(recentLnkFiles, path)

    case strings.HasSuffix(lowerPath, ".bmc"):
      rdpCache = append(rdpCache, path)

    case strings.Contains(lowerPath, "\\windows\\system32\\sru\\"):
      srumFiles = append(srumFiles, path)

    case strings.Contains(lowerPath, "\\wmi-activity\\") && strings.HasSuffix(lowerPath, ".etl"):
      wmiActivity = append(wmiActivity, path)

    case strings.Contains(lowerPath, "amcache.hve"):
      amcache = append(amcache, path)

    case strings.Contains(lowerPath, "windows defender") && strings.HasSuffix(lowerPath, ".log"):
      defenderLogs = append(defenderLogs, path)

    case strings.HasSuffix(lowerPath, ".etl"):
      eventTrace = append(eventTrace, path)

    case strings.Contains(lowerPath, "$mft"):
      mftFiles = append(mftFiles, path)

    }

    return nil
  })

  return prefetch, jumpList, registry, eventLogs, pageFiles, hiberFiles, memoryDumps, powershellHistory, browserCache, browserHistory, scheduledTasks,
    hostsFiles, lnkFiles, recycleBin, usnJrnl, windowsTimeline, scheduledTaskXMLs, werFiles, thumbcache, bitsJobs, recentLnkFiles, rdpCache,
    srumFiles, wmiActivity, amcache, defenderLogs, eventTrace, mftFiles
}

