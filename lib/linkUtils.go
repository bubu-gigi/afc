package utils

import (
	"fmt"
	"strings"
)

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

func ParseLinkFlags(flags uint32) map[string]bool {
	return map[string]bool{
		"HasLinkTargetIDList":         flags&HasLinkTargetIDList != 0,
		"HasLinkInfo":                 flags&HasLinkInfo != 0,
		"HasName":                     flags&HasName != 0,
		"HasRelativePath":             flags&HasRelativePath != 0,
		"HasWorkingDir":               flags&HasWorkingDir != 0,
		"HasArguments":                flags&HasArguments != 0,
		"HasIconLocation":             flags&HasIconLocation != 0,
		"IsUnicode":                   flags&IsUnicode != 0,
		"ForceNoLinkInfo":             flags&ForceNoLinkInfo != 0,
		"HasExpString":                flags&HasExpString != 0,
		"RunInSeparateProcess":        flags&RunInSeparateProcess != 0,
		"Unused1":                     flags&Unused1 != 0,
		"HasDarwinID":                 flags&HasDarwinID != 0,
		"RunAsUser":                   flags&RunAsUser != 0,
		"HasExpIcon":                  flags&HasExpIcon != 0,
		"NoPidlAlias":                 flags&NoPidlAlias != 0,
		"Unused2":                     flags&Unused2 != 0,
		"RunWithShimLayer":            flags&RunWithShimLayer != 0,
		"ForceNoLinkTrack":            flags&ForceNoLinkTrack != 0,
		"EnableTargetMetadata":        flags&EnableTargetMetadata != 0,
		"DisableLinkPathTracking":     flags&DisableLinkPathTracking != 0,
		"DisableKnownFolderTracking":  flags&DisableKnownFolderTracking != 0,
		"DisableKnownFolderAlias":     flags&DisableKnownFolderAlias != 0,
		"AllowLinkToLink":             flags&AllowLinkToLink != 0,
		"UnaliasOnSave":               flags&UnaliasOnSave != 0,
		"PreferEnvironmentPath":       flags&PreferEnvironmentPath != 0,
		"KeepLocalIDListForUNCTarget": flags&KeepLocalIDListForUNCTarget != 0,
	}
}

func ParseFileAttributesFlags(attributes uint32) map[string]bool {
	return map[string]bool{
		"Readonly":           attributes&Readonly != 0,
		"Hidden":             attributes&Hidden != 0,
		"System":             attributes&System != 0,
		"Reserved1":          attributes&Reserved1 != 0,
		"Directory":          attributes&Directory != 0,
		"Archive":            attributes&Archive != 0,
		"Reserved2":          attributes&Reserved2 != 0,
		"Normal":             attributes&Normal != 0,
		"Temporary":          attributes&Temporary != 0,
		"SparseFile":         attributes&SparseFile != 0,
		"ReparsePoint":       attributes&ReparsePoint != 0,
		"Compressed":         attributes&Compressed != 0,
		"Offline":            attributes&Offline != 0,
		"NotContentIndexed":  attributes&NotContentIndexed != 0,
		"Encrypted":          attributes&Encrypted != 0,
	}
}

func CheckShowCommand(v *uint32) {
	if *v != 1 && *v != 3 && *v != 7 {
		*v = 1
	}
}

func ParseHotKeyLowByte(b byte) string {
	switch b {
	case 0x00:
		return "None"
	case 0x30:
		return "0"
	case 0x31:
		return "1"
	case 0x32:
		return "2"
	case 0x33:
		return "3"
	case 0x34:
		return "4"
	case 0x35:
		return "5"
	case 0x36:
		return "6"
	case 0x37:
		return "7"
	case 0x38:
		return "8"
	case 0x39:
		return "9"
	case 0x41:
		return "A"
	case 0x42:
		return "B"
	case 0x43:
		return "C"
	case 0x44:
		return "D"
	case 0x45:
		return "E"
	case 0x46:
		return "F"
	case 0x47:
		return "G"
	case 0x48:
		return "H"
	case 0x49:
		return "I"
	case 0x4A:
		return "J"
	case 0x4B:
		return "K"
	case 0x4C:
		return "L"
	case 0x4D:
		return "M"
	case 0x4E:
		return "N"
	case 0x4F:
		return "O"
	case 0x50:
		return "P"
	case 0x51:
		return "Q"
	case 0x52:
		return "R"
	case 0x53:
		return "S"
	case 0x54:
		return "T"
	case 0x55:
		return "U"
	case 0x56:
		return "V"
	case 0x57:
		return "W"
	case 0x58:
		return "X"
	case 0x59:
		return "Y"
	case 0x5A:
		return "Z"
	case 0x70:
		return "F1"
	case 0x71:
		return "F2"
	case 0x72:
		return "F3"
	case 0x73:
		return "F4"
	case 0x74:
		return "F5"
	case 0x75:
		return "F6"
	case 0x76:
		return "F7"
	case 0x77:
		return "F8"
	case 0x78:
		return "F9"
	case 0x79:
		return "F10"
	case 0x7A:
		return "F11"
	case 0x7B:
		return "F12"
	case 0x7C:
		return "F13"
	case 0x7D:
		return "F14"
	case 0x7E:
		return "F15"
	case 0x7F:
		return "F16"
	case 0x80:
		return "F17"
	case 0x81:
		return "F18"
	case 0x82:
		return "F19"
	case 0x83:
		return "F20"
	case 0x84:
		return "F21"
	case 0x85:
		return "F22"
	case 0x86:
		return "F23"
	case 0x87:
		return "F24"
	case 0x90:
		return "NUM LOCK"
	case 0x91:
		return "SCROLL LOCK"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", b)
	}
}

func ParseHotKeyHighByte(b byte) string {
	modifiers := []string{}

	if b&0x01 != 0 {
		modifiers = append(modifiers, "SHIFT")
	}
	if b&0x02 != 0 {
		modifiers = append(modifiers, "CTRL")
	}
	if b&0x04 != 0 {
		modifiers = append(modifiers, "ALT")
	}

	if len(modifiers) == 0 {
		return "None"
	}
	return strings.Join(modifiers, "+")
}
