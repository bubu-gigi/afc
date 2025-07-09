package converters

import (
	utils "afc/lib"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
)

var (
	shellLink ShellLink
    linkFlags          map[string]bool
	fileAttributesFlags map[string]bool
	hotKeyLowByte      string
	hotKeyHighByte      string
)

func ConvertLinkToCsv(files []string) {
	for _, file := range files {
		convertLink(file)
	}
}
func convertLink(file string) error {
	var header [76]byte

	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.ReadFull(f, header[:])
	if err != nil {
		return fmt.Errorf("failed to read shell link header: %w", err)
	}

	readShellLinkHeader(header)

	if linkFlags["HasLinkTargetIDList"] {
		linkTargetIdList := readLinkTargetIDList(f)
		parseIDList(linkTargetIdList)
	}

	if linkFlags["HasLinkInfo"] {
		linkInfoBuf := make([]byte, 4)
		if _, err := io.ReadFull(f, linkInfoBuf); err != nil {
			return fmt.Errorf("failed to read LinkInfo size: %w", err)
		}
		linkInfoSize := binary.LittleEndian.Uint32(linkInfoBuf)
		linkInfoBuf = append(linkInfoBuf, make([]byte, linkInfoSize-4)...)
		if _, err := io.ReadFull(f, linkInfoBuf[4:]); err != nil {
			return fmt.Errorf("failed to read full LinkInfo structure: %w", err)
		}
		readLinkInfo(linkInfoBuf)
	}

	readStringData(f)
	readExtraData(f)

	fileOut := utils.CreateOutputFile(file) 
	defer fileOut.Close()

	writer := csv.NewWriter(fileOut) 
	defer writer.Flush()

	headers := []string{
		"File", "CreationTime", "AccessTime", "WriteTime", "FileSize", "IconIndex", "ShowCommand", "HotKey",
		"Flags", "FileAttributes", "RelativePath", "WorkingDirectory", "CommandLineArguments", "IconLocation", "NameString",
		"LocalBasePath", "CommonPathSuffix", "VolumeLabel", "DriveType", "DriveSerialNumber",
	}
	writer.Write(headers)

	record := []string{
		file,
		utils.FileTimeToString(shellLink.Header.CreationTime),
		utils.FileTimeToString(shellLink.Header.AccessTime),
		utils.FileTimeToString(shellLink.Header.WriteTime),
		strconv.Itoa(int(shellLink.Header.FileSize)),
		strconv.Itoa(int(shellLink.Header.IconIndex)),
		strconv.Itoa(int(shellLink.Header.ShowCommand)),
		hotKeyLowByte + "+" + hotKeyHighByte,
		utils.FormatMapKeys(linkFlags),
		utils.FormatMapKeys(fileAttributesFlags),
		shellLink.StringData.RelativePath,
		shellLink.StringData.WorkingDirectory,
		shellLink.StringData.CommandLineArguments,
		shellLink.StringData.IconLocation,
		shellLink.StringData.NameString,
		string(shellLink.LinkInfo.LocalBasePath),
		string(shellLink.LinkInfo.CommonPathSuffix),
		string(shellLink.LinkInfo.VolumeID.Data),
		strconv.Itoa(int(shellLink.LinkInfo.VolumeID.DriveType)),
		strconv.FormatUint(uint64(shellLink.LinkInfo.VolumeID.DriveSerialNumber), 10),
	}
	writer.Write(record)

	return nil
}


func readShellLinkHeader(header [76]byte) {
	//validate the header size to be 76
	shellLink.Header.HeaderSize = binary.LittleEndian.Uint32(header[:4])
	if shellLink.Header.HeaderSize != 0x0000004C {
		log.Fatal("link.header -> Error: headerSize wrong")
		os.Exit(1)
	}

	//validate the clsid
	var linkCLSID [16]byte
	copy(linkCLSID[:], header[4:20])
	shellLink.Header.LinkCLSID = linkCLSID
	var expectedCLSID = [16]byte{0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	if shellLink.Header.LinkCLSID != expectedCLSID {
		log.Fatal("link.header -> Error: clsid wrong")
		os.Exit(1)
	}

	//read props
	shellLink.Header.LinkFlags = binary.LittleEndian.Uint32(header[20:24])
	shellLink.Header.FileAttributes = binary.LittleEndian.Uint32(header[24:28])
	shellLink.Header.CreationTime = binary.LittleEndian.Uint64(header[28:36])
	shellLink.Header.AccessTime = binary.LittleEndian.Uint64(header[36:44])
	shellLink.Header.WriteTime = binary.LittleEndian.Uint64(header[44:52])
	shellLink.Header.FileSize = binary.LittleEndian.Uint32(header[52:56])
	shellLink.Header.IconIndex = binary.LittleEndian.Uint32(header[56:60])
	shellLink.Header.ShowCommand = binary.LittleEndian.Uint32(header[60:64])
	checkShowCommand(&shellLink.Header.ShowCommand)
	shellLink.Header.HotKey = binary.LittleEndian.Uint16(header[64:66])
	shellLink.Header.Reserved1 = binary.LittleEndian.Uint16(header[66:68])
	utils.CheckNullUint16(shellLink.Header.Reserved1)
	shellLink.Header.Reserved2 = binary.LittleEndian.Uint32(header[68:72])
	utils.CheckNullUint32(shellLink.Header.Reserved2)
	shellLink.Header.Reserved3 = binary.LittleEndian.Uint32(header[72:76])
	utils.CheckNullUint32(shellLink.Header.Reserved3)
	//populate flags and hotKeys
	linkFlags = parseLinkFlags(shellLink.Header.LinkFlags)
	fileAttributesFlags = parseFileAttributesFlags(shellLink.Header.FileAttributes)
	hotKeyLowByte = parseHotKeyLowByte(header[64])
	hotKeyHighByte = parseHotKeyHighByte(header[65])
}

func readLinkTargetIDList(r io.Reader) []byte {
	// bytes for the size
	var sizeBuf [2]byte
	_, err := io.ReadFull(r, sizeBuf[:])
	if err != nil {
		fmt.Printf("failed to read IDListSize: %v\n", err)
		return nil
	}

	idListSize := binary.LittleEndian.Uint16(sizeBuf[:])
	if idListSize == 0 {
		return nil
	}

	// the list
	idList := make([]byte, idListSize)
	_, err = io.ReadFull(r, idList)
	if err != nil {
		fmt.Printf("failed to read IDList: %v\n", err)
		return nil
	}

	shellLink.LinkTargetIdList.IdListSize = idListSize
	return idList
}


func parseIDList(data []byte) {
	var items []ItemId
	offset := 0

	for {
		if offset+2 > len(data) {
			return 
			//fmt.Print("unexpected end of IDList, missing terminal ID")
		}

		itemSize := binary.LittleEndian.Uint16(data[offset : offset+2])

		// TERMINALID
		if itemSize == 0x0000 {
			break
		}

		if offset+int(itemSize) > len(data) {
			return
			//fmt.Fprint("invalid ItemID: size %d exceeds buffer at offset %d", itemSize, offset)
		}

		item := ItemId{
			Size: itemSize,
			Data: data[offset+2 : offset+int(itemSize)],
		}
		items = append(items, item)

		offset += int(itemSize)
	}

	shellLink.LinkTargetIdList.ItemIdList = items 
}

func readLinkInfo(data []byte) {
	shellLink.LinkInfo.LinkInfoSize = binary.LittleEndian.Uint32(data[:4])
	shellLink.LinkInfo.LinkInfoHeaderSize = binary.LittleEndian.Uint32(data[4:8])
	shellLink.LinkInfo.LinkInfoFlags = binary.LittleEndian.Uint32(data[8:12])
	shellLink.LinkInfo.VolumeIDOffset = binary.LittleEndian.Uint32(data[12:16])
	shellLink.LinkInfo.LocalBasePathOffset = binary.LittleEndian.Uint32(data[16:20])
	shellLink.LinkInfo.CommonNetworkRelativeLinkOffset = binary.LittleEndian.Uint32(data[20:24])
	shellLink.LinkInfo.CommonPathSuffixOffset = binary.LittleEndian.Uint32(data[24:28])
	shellLink.LinkInfo.LocalBasePathOffsetUnicode = binary.LittleEndian.Uint32(data[28:32])
	shellLink.LinkInfo.CommonPathSuffixOffsetUnicode = binary.LittleEndian.Uint32(data[32:36])

	if shellLink.LinkInfo.VolumeIDOffset != 0 {
		parseVolumeId(data, shellLink.LinkInfo.VolumeIDOffset)
	}

	if shellLink.LinkInfo.LocalBasePathOffset != 0 {
		offset := shellLink.LinkInfo.LocalBasePathOffset
		end := utils.FindNullTerminator(data[offset:])
		shellLink.LinkInfo.LocalBasePath = data[offset : offset+uint32(end)]
	}

	if shellLink.LinkInfo.CommonPathSuffixOffset != 0 {
		offset := shellLink.LinkInfo.CommonPathSuffixOffset
		end := utils.FindNullTerminator(data[offset:])
		shellLink.LinkInfo.CommonPathSuffix = data[offset : offset+uint32(end)]
	}
}

func parseVolumeId(data []byte, offset uint32) {
	if int(offset)+16 > len(data) {
		fmt.Println("VolumeID structure too short")
	}

	start := int(offset)

	shellLink.LinkInfo.VolumeID.VolumeIdSize = binary.LittleEndian.Uint32(data[start:start+4])
	shellLink.LinkInfo.VolumeID.DriveType = binary.LittleEndian.Uint32(data[start+4:start+8])
	shellLink.LinkInfo.VolumeID.DriveSerialNumber = binary.LittleEndian.Uint32(data[start+8:start+12])
	shellLink.LinkInfo.VolumeID.VolumeLabelOffset = binary.LittleEndian.Uint32(data[start+12:start+16])
	if shellLink.LinkInfo.VolumeID.VolumeLabelOffset == 20 {
		shellLink.LinkInfo.VolumeID.VolumeLabelOffsetUnicode = binary.LittleEndian.Uint32(data[start+16:start+20])
	}

	var label string
	if shellLink.LinkInfo.VolumeID.VolumeLabelOffset != 0x14 {
		labelStart := start + int(shellLink.LinkInfo.VolumeID.VolumeLabelOffset)
		end := utils.FindNullTerminator(data[labelStart:])
		labelBytes := data[labelStart : labelStart+end]
		label = string(labelBytes) 
	} else {
		unicodeStart := start + int(shellLink.LinkInfo.VolumeID.VolumeLabelOffsetUnicode)
		end := utils.FindNullTerminator(data[unicodeStart:])
		labelBytes := data[unicodeStart : unicodeStart+end]
		label = utils.DecodeUTF16String(labelBytes)
	}

	shellLink.LinkInfo.VolumeID.Data = []byte(label)
}

func readStringData(r io.Reader) {
	readString := func() string {
		var count uint16
		binary.Read(r, binary.LittleEndian, &count)
		if count == 0 {
			return ""
		}

		if linkFlags["IsUnicode"] {
			buf := make([]byte, count*2)
			io.ReadFull(r, buf)
			return utils.DecodeUTF16String(buf)
		} else {
			buf := make([]byte, count)
			io.ReadFull(r, buf)
			return string(buf)
		}
	}

	if linkFlags["HasName"] {
		shellLink.StringData.NameString = readString()
	}
	if linkFlags["HasRelativePath"] {
		shellLink.StringData.RelativePath = readString()
	}
	if linkFlags["HasWorkingDir"] {
		shellLink.StringData.WorkingDirectory = readString()
	}
	if linkFlags["HasArguments"] {
		shellLink.StringData.CommandLineArguments = readString()
	}
	if linkFlags["HasIconLocation"] {
		shellLink.StringData.IconLocation = readString()
	}
}


func readExtraData(r io.Reader) {
	
}

func parseLinkFlags(flags uint32) map[string]bool {
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

func parseFileAttributesFlags(attributes uint32) map[string]bool {
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

func checkShowCommand(v *uint32) {
	if *v != 1 && *v != 3 && *v != 7 {
		*v = 1
	}
}

func parseHotKeyLowByte(b byte) string {
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

func parseHotKeyHighByte(b byte) string {
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
