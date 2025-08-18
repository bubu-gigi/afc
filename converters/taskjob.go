package converters

import (
	"afc/config"
	"afc/flags"
	utils "afc/lib"
	"encoding/binary"
	"fmt"
	"log"
	"os"
)

func ConvertTaskJobToCsv(files []string, cfg *config.Config, opts *flags.GlobalOptions) {
	for _, file := range files {
		convertTaskJob(file, cfg, opts)
	}
}

func convertTaskJob(file string, cfg *config.Config, opts *flags.GlobalOptions) error {
	f, err := os.Open(file)
	if err != nil {
		log.Printf("taskjob: error opening file %s: %v", file, err)
		return nil
	}
	defer f.Close()

	header := &JobHeader{}
	if err := readHeader(f, header); err != nil {
		log.Printf("taskjob: error reading header for file %s: %v", file, err)
		return nil
	}

	instanceCount, appName, params, workingDir, author, comment, userData, reservedData, err := readDataSection(f)
	if err != nil {
		log.Printf("taskjob: error reading data section for file %s: %v", file, err)
		return nil
	}

	triggers, err := readTriggers(f)
	if err != nil {
		log.Printf("taskjob: error reading triggers for file %s: %v", file, err)
		return nil
	}

	headers := []string{
		"ProductVersion", "FormatVersion", "AppNameOffset", "TriggerOffset",
		"ErrorRetryCount", "ErrorRetryInterval", "IdleDeadline", "IdleWait", "Priority", "MaxRunTime",
		"RunningInstanceCount", "ApplicationName", "Parameters", "WorkingDirectory", "Author", "Comment",
		"UserData", "ReservedData", "TriggerCount",
	}

	record := []string{
		fmt.Sprintf("%d", header.ProductVersion),
		fmt.Sprintf("%d", header.FileVersion),
		fmt.Sprintf("0x%X", header.AppNameOffset),
		fmt.Sprintf("0x%X", header.TriggerOffset),
		fmt.Sprintf("%d", header.ErrorRetryCount),
		fmt.Sprintf("%d", header.ErrorRetryInterval),
		fmt.Sprintf("%d", header.IdleDeadline),
		fmt.Sprintf("%d", header.IdleWait),
		fmt.Sprintf("%d", header.Priority),
		fmt.Sprintf("%d", header.MaxRunTime),
		fmt.Sprintf("%d", instanceCount),
		appName,
		params,
		workingDir,
		author,
		comment,
		string(userData),
		fmt.Sprintf("%x", reservedData),
		fmt.Sprintf("%d", len(triggers)),
	}

	utils.HandleArtifactConverted(cfg, "job", file, headers, [][]string{record}, opts.SkipWazuhSend)

	triggerHeaders := []string{
		"Index", "BeginDate", "EndDate", "StartTime", "DurationMin", "IntervalMin",
		"Flags", "TriggerType", "TriggerSpecific0", "TriggerSpecific1", "TriggerSpecific2",
	}

	var triggerRows [][]string
	for i, t := range triggers {
		begin := fmt.Sprintf("%04d-%02d-%02d", t.BeginYear, t.BeginMonth, t.BeginDay)
		end := ""
		if t.Flags&0x1 != 0 {
			end = fmt.Sprintf("%04d-%02d-%02d", t.EndYear, t.EndMonth, t.EndDay)
		}
		start := fmt.Sprintf("%02d:%02d", t.StartHour, t.StartMinute)

		triggerRows = append(triggerRows, []string{
			fmt.Sprintf("%d", i+1),
			begin,
			end,
			start,
			fmt.Sprintf("%d", t.MinutesDuration),
			fmt.Sprintf("%d", t.MinutesInterval),
			fmt.Sprintf("0x%X", t.Flags),
			fmt.Sprintf("%d", t.TriggerType),
			fmt.Sprintf("%d", t.TriggerSpecific0),
			fmt.Sprintf("%d", t.TriggerSpecific1),
			fmt.Sprintf("%d", t.TriggerSpecific2),
		})
	}

	utils.HandleArtifactConverted(cfg, "job", file, triggerHeaders, triggerRows, opts.SkipWazuhSend)

	return nil
}

func readHeader(file *os.File, header *JobHeader) error {
	return binary.Read(file, binary.LittleEndian, header)
}

func readDataSection(f *os.File) (uint16, string, string, string, string, string, []byte, []byte, error) {
	var instanceCount uint16
	if err := binary.Read(f, binary.LittleEndian, &instanceCount); err != nil {
		return 0, "", "", "", "", "", nil, nil, err
	}

	appName, err := utils.ReadFullUnicodeString(f)
	if err != nil {
		return 0, "", "", "", "", "", nil, nil, err
	}
	params, err := utils.ReadFullUnicodeString(f)
	if err != nil {
		return 0, "", "", "", "", "", nil, nil, err
	}
	workingDir, err := utils.ReadFullUnicodeString(f)
	if err != nil {
		return 0, "", "", "", "", "", nil, nil, err
	}
	author, err := utils.ReadFullUnicodeString(f)
	if err != nil {
		return 0, "", "", "", "", "", nil, nil, err
	}
	comment, err := utils.ReadFullUnicodeString(f)
	if err != nil {
		return 0, "", "", "", "", "", nil, nil, err
	}

	var userDataSize uint16
	if err := binary.Read(f, binary.LittleEndian, &userDataSize); err != nil {
		return 0, "", "", "", "", "", nil, nil, err
	}

	var userData []byte
	if userDataSize > 0 {
		userData = make([]byte, userDataSize)
		if _, err := f.Read(userData); err != nil {
			return 0, "", "", "", "", "", nil, nil, err
		}
	}

	var reservedDataSize uint16
	if err := binary.Read(f, binary.LittleEndian, &reservedDataSize); err != nil {
		return 0, "", "", "", "", "", nil, nil, err
	}

	var reservedData []byte
	if reservedDataSize > 0 {
		reservedData = make([]byte, reservedDataSize)
		if _, err := f.Read(reservedData); err != nil {
			return 0, "", "", "", "", "", nil, nil, err
		}
	}

	return instanceCount, appName, params, workingDir, author, comment, userData, reservedData, nil
}

func readTriggers(f *os.File) ([]JobTrigger, error) {
	var triggerSizeBytes uint16
	if err := binary.Read(f, binary.LittleEndian, &triggerSizeBytes); err != nil {
		return nil, err
	}

	numTriggers := int(triggerSizeBytes) / 48
	triggers := make([]JobTrigger, 0, numTriggers)

	for i := 0; i < numTriggers; i++ {
		var t JobTrigger
		if err := binary.Read(f, binary.LittleEndian, &t); err != nil {
			return nil, err
		}
		triggers = append(triggers, t)
	}

	return triggers, nil
}
