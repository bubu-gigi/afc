package converters

//https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/96446df7-7683-40e0-a713-b01933b93b18

import (
	utils "afc/lib"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"os"
	"strings"
)


func ConvertTaskJobToCsv(files []string) {
	for _, file := range files {
		convertTaskJob(file)
	}
}

func convertTaskJob(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	header := &JobHeader{}
	err = readHeader(f, header)
	if err != nil {
		return err
	}

	instanceCount, appName, params, workingDir, author, comment, userData, reservedData, err := readDataSection(f)
	if err != nil {
		return err
	}

	triggers, err := readTriggers(f)
	if err != nil {
		return err
	}

	fileOut := utils.CreateOutputFile(file)
	defer fileOut.Close()

	writer := csv.NewWriter(fileOut)
	defer writer.Flush()

	writer.Write([]string{
		"ProductVersion", "FormatVersion", "AppNameOffset", "TriggerOffset",
		"ErrorRetryCount", "ErrorRetryInterval", "IdleDeadline", "IdleWait", "Priority", "MaxRunTime",
		"RunningInstanceCount", "ApplicationName", "Parameters", "WorkingDirectory", "Author", "Comment",
		"UserData", "ReservedData", "TriggerCount",
	})

	writer.Write([]string{
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
	})

	triggerOut, err := createTriggerOutputFile(file)
	if err != nil {
		return err
	}
	defer triggerOut.Close()

	triggerWriter := csv.NewWriter(triggerOut)
	defer triggerWriter.Flush()

	triggerWriter.Write([]string{
		"Index", "BeginDate", "EndDate", "StartTime", "DurationMin", "IntervalMin",
		"Flags", "TriggerType", "TriggerSpecific0", "TriggerSpecific1", "TriggerSpecific2",
	})

	for i, t := range triggers {
		begin := fmt.Sprintf("%04d-%02d-%02d", t.BeginYear, t.BeginMonth, t.BeginDay)
		end := ""
		if t.Flags&0x1 != 0 { 
			end = fmt.Sprintf("%04d-%02d-%02d", t.EndYear, t.EndMonth, t.EndDay)
		}
		start := fmt.Sprintf("%02d:%02d", t.StartHour, t.StartMinute)

		triggerWriter.Write([]string{
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

	return nil
}

func readHeader(file *os.File, header *JobHeader) error {
	return binary.Read(file, binary.LittleEndian, header)
}

func readDataSection(f *os.File) (uint16, string, string, string, string, string, []byte, []byte, error) {
	var instanceCount uint16
	err := binary.Read(f, binary.LittleEndian, &instanceCount)
	if err != nil {
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
	err = binary.Read(f, binary.LittleEndian, &userDataSize)
	if err != nil {
		return 0, "", "", "", "", "", nil, nil, err
	}

	var userData []byte
	if userDataSize > 0 {
		userData = make([]byte, userDataSize)
		_, err = f.Read(userData)
		if err != nil {
			return 0, "", "", "", "", "", nil, nil, err
		}
	}

	var reservedDataSize uint16
	err = binary.Read(f, binary.LittleEndian, &reservedDataSize)
	if err != nil {
		return 0, "", "", "", "", "", nil, nil, err
	}

	var reservedData []byte
	if reservedDataSize > 0 {
		reservedData = make([]byte, reservedDataSize)
		_, err = f.Read(reservedData)
		if err != nil {
			return 0, "", "", "", "", "", nil, nil, err
		}
	}

	return instanceCount, appName, params, workingDir, author, comment, userData, reservedData, nil
}

func readTriggers(f *os.File) ([]JobTrigger, error) {
	var triggerSizeBytes uint16
	err := binary.Read(f, binary.LittleEndian, &triggerSizeBytes)
	if err != nil {
		return nil, err
	}

	numTriggers := int(triggerSizeBytes) / 48
	triggers := make([]JobTrigger, 0, numTriggers)

	for i := 0; i < numTriggers; i++ {
		var t JobTrigger
		err := binary.Read(f, binary.LittleEndian, &t)
		if err != nil {
			return nil, err
		}
		triggers = append(triggers, t)
	}

	return triggers, nil
}

func createTriggerOutputFile(base string) (*os.File, error) {
	outPath := strings.TrimSuffix(base, ".job") + "_triggers.csv"
	return os.Create(outPath)
}
