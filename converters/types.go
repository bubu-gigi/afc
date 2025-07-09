package converters

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
