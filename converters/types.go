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

const (
	HasLinkTargetIDList         = 1 << 0
	HasLinkInfo                 = 1 << 1
	HasName                     = 1 << 2
	HasRelativePath             = 1 << 3
	HasWorkingDir               = 1 << 4
	HasArguments                = 1 << 5
	HasIconLocation             = 1 << 6
	IsUnicode                   = 1 << 7
	ForceNoLinkInfo             = 1 << 8
	HasExpString                = 1 << 9
	RunInSeparateProcess        = 1 << 10
	Unused1                     = 1 << 11
	HasDarwinID                 = 1 << 12
	RunAsUser                   = 1 << 13
	HasExpIcon                  = 1 << 14
	NoPidlAlias                 = 1 << 15
	Unused2                     = 1 << 16
	RunWithShimLayer            = 1 << 17
	ForceNoLinkTrack            = 1 << 18
	EnableTargetMetadata        = 1 << 19
	DisableLinkPathTracking     = 1 << 20
	DisableKnownFolderTracking  = 1 << 21
	DisableKnownFolderAlias     = 1 << 22
	AllowLinkToLink             = 1 << 23
	UnaliasOnSave               = 1 << 24
	PreferEnvironmentPath       = 1 << 25
	KeepLocalIDListForUNCTarget = 1 << 26
)

const (
	Readonly         			= 1 << 0
	Hidden                 		= 1 << 1
	System                      = 1 << 2
	Reserved1                   = 1 << 3
	Directory                   = 1 << 4
	Archive                     = 1 << 5
	Reserved2                   = 1 << 6
	Normal                      = 1 << 7
	Temporary                   = 1 << 8
	SparseFile                  = 1 << 9
	ReparsePoint                = 1 << 10
	Compressed                  = 1 << 11
	Offline                     = 1 << 12
	NotContentIndexed           = 1 << 13
	Encrypted                   = 1 << 14
)
