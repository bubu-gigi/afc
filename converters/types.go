package converters

import (
	"encoding/xml"
	"time"
)

type ShellLinkHeader struct {
	HeaderSize     uint32
	LinkCLSID      [16]byte
	LinkFlags      uint32
	FileAttributes uint32
	CreationTime   uint64
	AccessTime     uint64
	WriteTime      uint64
	FileSize       uint32
	IconIndex      uint32
	ShowCommand    uint32
	HotKey		   uint16
	Reserved1      uint16
	Reserved2      uint32
	Reserved3 	   uint32
}

type LinkTargetIdList struct {
	IdListSize uint16
	ItemIdList []ItemId
	TerminalId uint16
}

type ItemId struct {
	Size uint16
	Data []byte
}

type VolumeId struct {
	VolumeIdSize uint32
	DriveType uint32
	DriveSerialNumber uint32
	VolumeLabelOffset uint32
	VolumeLabelOffsetUnicode uint32
	Data []byte
}

type CommonNetworkRelativeLink struct {
	CommonNetworkRelativeLinkSize uint32
	CommonNetworkRelativeLinkFlags uint32
	NetNameOffset uint32
	DeviceNameOffset uint32
	NetworkProviderType uint32
	NetNameOffsetUnicode uint32
	DeviceNameOffsetUnicode uint32
	NetName []byte
	DeviceName []byte
	NetNameUnicode []byte
	DeviceNameUnicode []byte
}

type LinkInfo struct {
	LinkInfoSize uint32
	LinkInfoHeaderSize uint32
	LinkInfoFlags uint32
	VolumeIDOffset uint32
	LocalBasePathOffset uint32
	CommonNetworkRelativeLinkOffset uint32
	CommonPathSuffixOffset uint32
	LocalBasePathOffsetUnicode uint32
	CommonPathSuffixOffsetUnicode uint32
	VolumeID VolumeId
	LocalBasePath []byte
	CommonNetworkRelativeLink CommonNetworkRelativeLink
	CommonPathSuffix []byte
	LocalBasePathUnicode []byte
	CommonPathSuffixUnicode []byte
}

type StringData struct {
	NameString           string
	RelativePath         string
	WorkingDirectory     string
	CommandLineArguments string
	IconLocation         string
}

type ShellLink struct {
	Header ShellLinkHeader
	LinkTargetIdList LinkTargetIdList
	LinkInfo LinkInfo
	StringData StringData
}

//Jobs v.1

type JobHeader struct {
	ProductVersion      uint16
	FileVersion 		uint16
	UUID                [16]byte
	AppNameOffset       uint32
	TriggerOffset       uint32
	ErrorRetryCount     uint16
	ErrorRetryInterval  uint16
	IdleDeadline        uint16
	IdleWait            uint16
	Priority            uint32
	MaxRunTime          uint32
	ExitCode 			uint32 
	Status 				uint32
	Flags  				uint32
}

type JobTrigger struct {
	TriggerSize       uint16 // always 0x30
	Reserved1         uint16
	BeginYear         uint16
	BeginMonth        uint16
	BeginDay          uint16
	EndYear           uint16
	EndMonth          uint16
	EndDay            uint16
	StartHour         uint16
	StartMinute       uint16
	MinutesDuration   uint32
	MinutesInterval   uint32
	Flags             uint32
	TriggerType       uint32
	TriggerSpecific0  uint16
	TriggerSpecific1  uint16
	TriggerSpecific2  uint16
	Padding           uint16
	Reserved2         uint16
	Reserved3         uint16
}

// Jobs v.2 XML

type Task struct {
	XMLName      xml.Name     `xml:"Task"`
	Registration Registration `xml:"RegistrationInfo"`
	Principals   Principals   `xml:"Principals"`
	Actions      Actions      `xml:"Actions"`
	Triggers     Triggers     `xml:"Triggers"`
}

type Registration struct {
	Author string `xml:"Author"`
}

type Principals struct {
	Principal []Principal `xml:"Principal"`
}

type Principal struct {
	UserID    string `xml:"UserId"`
	LogonType string `xml:"LogonType"`
}

type Triggers struct {
	TimeTrigger []TimeTrigger `xml:"TimeTrigger"`
}

type TimeTrigger struct {
	StartBoundary string `xml:"StartBoundary"`
	Enabled       string `xml:"Enabled"`
}

type Actions struct {
	Exec []ExecAction `xml:"Exec"`
}

type ExecAction struct {
	Command   string `xml:"Command"`
	Arguments string `xml:"Arguments"`
}

// UsrJrnl

type UsnRecord struct {
	RecordLength           uint32
	MajorVersion           uint16
	MinorVersion           uint16
	FileReferenceNumber    uint64
	ParentFileReferenceNum uint64
	Usn                    uint64
	Timestamp              time.Time
	Reason                 uint32
	SourceInfo             uint32
	SecurityID             uint32
	FileAttributes         uint32
	FileName               string
}

var ReasonFlags = map[uint32]string{
	0x00000001: "DataOverwrite",
	0x00000002: "DataExtend",
	0x00000004: "DataTruncation",
	0x00000010: "NamedDataOverwrite",
	0x00000020: "NamedDataExtend",
	0x00000040: "NamedDataTruncation",
	0x00000100: "FileCreate",
	0x00000200: "FileDelete",
	0x00000400: "EaChange",
	0x00000800: "SecurityChange",
	0x00001000: "RenameOldName",
	0x00002000: "RenameNewName",
	0x00004000: "IndexableChange",
	0x00008000: "BasicInfoChange",
	0x00010000: "HardLinkChange",
	0x00020000: "CompressionChange",
	0x00040000: "EncryptionChange",
	0x00080000: "ObjectIdChange",
	0x00100000: "ReparsePointChange",
	0x00200000: "StreamChange",
	0x80000000: "Close",
}
