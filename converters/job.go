package converters

import (
	utils "afc/lib"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"os"
)

type JobFileHeader struct {
	ProductVersion      uint16
	FormatVersion       uint16
	UUID                [16]byte
	AppNameOffset       uint32
	TriggerOffset       uint32
	ErrorRetryCount     uint16
	ErrorRetryInterval  uint16
	IdleDeadline        uint32
	IdleWait            uint32
	Priority            uint8
	MaxRunTime          uint32
}

func ConvertJobToCsv(files []string) {
	for _, file := range files {
		convertJob(file)
	}
}

func convertJob(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	header := &JobFileHeader{}
	err = binary.Read(f, binary.LittleEndian, header)
	if err != nil {
		return err
	}

	fileOut := utils.CreateOutputFile(file)
	defer fileOut.Close()

	writer := csv.NewWriter(fileOut)
	defer writer.Flush()

	writer.Write([]string{
		"Path", "ProductVersion", "FormatVersion", "AppNameOffset", "TriggerOffset",
		"ErrorRetryCount", "ErrorRetryInterval", "IdleDeadline", "IdleWait", "Priority", "MaxRunTime",
	})

	writer.Write([]string{
		file,
		fmt.Sprintf("%d", header.ProductVersion),
		fmt.Sprintf("%d", header.FormatVersion),
		fmt.Sprintf("0x%X", header.AppNameOffset),
		fmt.Sprintf("0x%X", header.TriggerOffset),
		fmt.Sprintf("%d", header.ErrorRetryCount),
		fmt.Sprintf("%d", header.ErrorRetryInterval),
		fmt.Sprintf("%d", header.IdleDeadline),
		fmt.Sprintf("%d", header.IdleWait),
		fmt.Sprintf("%d", header.Priority),
		fmt.Sprintf("%d", header.MaxRunTime),
	})

	return nil
}