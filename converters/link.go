package converters

import (
	"afc/config"
	utils "afc/lib"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
)

var (
	shellLink           ShellLink
	linkFlags           map[string]bool
	fileAttributesFlags map[string]bool
	hotKeyLowByte       string
	hotKeyHighByte      string
	parsedItems         []string
)

func ConvertLinkToCsv(files []string, config *config.Config) {
	for _, file := range files {
		if err := convertLink(file, config); err != nil {
			log.Printf("[ERROR] Failed to convert LNK file %s: %v", file, err)
		}
	}
}

func convertLink(file string, config *config.Config) error {
	var header [76]byte

	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("cannot open LNK file: %w", err)
	}
	defer f.Close()

	if _, err = io.ReadFull(f, header[:]); err != nil {
		return fmt.Errorf("failed to read shell link header: %w", err)
	}
	if err := readShellLinkHeader(header); err != nil {
		return err
	}

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

	headers := []string{
		"File", "CreationTime", "AccessTime", "WriteTime", "FileSize", "IconIndex", "ShowCommand", "HotKey",
		"Flags", "FileAttributes", "RelativePath", "WorkingDirectory", "CommandLineArguments", "IconLocation", "NameString",
		"LocalBasePath", "CommonPathSuffix", "VolumeLabel", "DriveType", "DriveSerialNumber", "ItemIdListReadable",
		"NetName", "DeviceName", "NetworkProviderType", "CommonNetworkRelativeLinkFlags",
	}

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
		strings.Join(parsedItems, "|"),
		string(shellLink.LinkInfo.CommonNetworkRelativeLink.NetName),
		string(shellLink.LinkInfo.CommonNetworkRelativeLink.DeviceName),
		strconv.FormatUint(uint64(shellLink.LinkInfo.CommonNetworkRelativeLink.NetworkProviderType), 10),
		fmt.Sprintf("0x%08X", shellLink.LinkInfo.CommonNetworkRelativeLink.CommonNetworkRelativeLinkFlags),
	}

	rows := [][]string{record}
	if err := utils.SendCsvToWazuh(config, headers, rows); err != nil {
		return fmt.Errorf("failed to send .lnk CSV to Wazuh: %w", err)
	}

	log.Printf("[INFO] Converted LNK file %s", file)
	return nil
}

func readShellLinkHeader(header [76]byte) error {
	shellLink.Header.HeaderSize = binary.LittleEndian.Uint32(header[:4])
	if shellLink.Header.HeaderSize != 0x0000004C {
		return fmt.Errorf("invalid ShellLink header size")
	}
	var expectedCLSID = [16]byte{0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	var linkCLSID [16]byte
	copy(linkCLSID[:], header[4:20])
	shellLink.Header.LinkCLSID = linkCLSID
	if shellLink.Header.LinkCLSID != expectedCLSID {
		return fmt.Errorf("invalid ShellLink CLSID")
	}

	shellLink.Header.LinkFlags = binary.LittleEndian.Uint32(header[20:24])
	shellLink.Header.FileAttributes = binary.LittleEndian.Uint32(header[24:28])
	shellLink.Header.CreationTime = binary.LittleEndian.Uint64(header[28:36])
	shellLink.Header.AccessTime = binary.LittleEndian.Uint64(header[36:44])
	shellLink.Header.WriteTime = binary.LittleEndian.Uint64(header[44:52])
	shellLink.Header.FileSize = binary.LittleEndian.Uint32(header[52:56])
	shellLink.Header.IconIndex = binary.LittleEndian.Uint32(header[56:60])
	shellLink.Header.ShowCommand = binary.LittleEndian.Uint32(header[60:64])
	utils.CheckShowCommand(&shellLink.Header.ShowCommand)
	shellLink.Header.HotKey = binary.LittleEndian.Uint16(header[64:66])
	shellLink.Header.Reserved1 = binary.LittleEndian.Uint16(header[66:68])
	utils.CheckNullUint16(shellLink.Header.Reserved1)
	shellLink.Header.Reserved2 = binary.LittleEndian.Uint32(header[68:72])
	utils.CheckNullUint32(shellLink.Header.Reserved2)
	shellLink.Header.Reserved3 = binary.LittleEndian.Uint32(header[72:76])
	utils.CheckNullUint32(shellLink.Header.Reserved3)

	linkFlags = utils.ParseLinkFlags(shellLink.Header.LinkFlags)
	fileAttributesFlags = utils.ParseFileAttributesFlags(shellLink.Header.FileAttributes)
	hotKeyLowByte = utils.ParseHotKeyLowByte(header[64])
	hotKeyHighByte = utils.ParseHotKeyHighByte(header[65])
	return nil
}

func readLinkTargetIDList(r io.Reader) []byte {
	var sizeBuf [2]byte
	if _, err := io.ReadFull(r, sizeBuf[:]); err != nil {
		log.Printf("[WARNING] Failed to read IDListSize: %v", err)
		return nil
	}
	idListSize := binary.LittleEndian.Uint16(sizeBuf[:])
	if idListSize == 0 {
		return nil
	}
	idList := make([]byte, idListSize)
	if _, err := io.ReadFull(r, idList); err != nil {
		log.Printf("[WARNING] Failed to read IDList: %v", err)
		return nil
	}
	shellLink.LinkTargetIdList.IdListSize = idListSize
	return idList
}

func parseIDList(data []byte) {
	offset := 0
	for {
		if offset+2 > len(data) {
			return
		}
		itemSize := binary.LittleEndian.Uint16(data[offset : offset+2])
		if itemSize == 0x0000 {
			break
		}
		if offset+int(itemSize) > len(data) {
			return
		}
		item := ItemId{
			Size: itemSize,
			Data: data[offset+2 : offset+int(itemSize)],
		}
		shellLink.LinkTargetIdList.ItemIdList = append(shellLink.LinkTargetIdList.ItemIdList, item)
		parsedItems = append(parsedItems, parseItemIdToString(item))
		offset += int(itemSize)
	}
}

func parseItemIdToString(item ItemId) string {
	str := string(item.Data)
	if utils.IsPrintable(str) {
		return str
	}
	return fmt.Sprintf("% X", item.Data)
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

	if shellLink.LinkInfo.CommonNetworkRelativeLinkOffset != 0 {
		parseCommonNetworkRelativeLink(data, shellLink.LinkInfo.CommonNetworkRelativeLinkOffset)
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

func readStringData(r io.Reader) {
	readString := func() string {
		var count uint16
		if err := binary.Read(r, binary.LittleEndian, &count); err != nil || count == 0 {
			return ""
		}
		if linkFlags["IsUnicode"] {
			buf := make([]byte, count*2)
			if _, err := io.ReadFull(r, buf); err != nil {
				return ""
			}
			return utils.DecodeUTF16String(buf)
		} else {
			buf := make([]byte, count)
			if _, err := io.ReadFull(r, buf); err != nil {
				return ""
			}
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
	for {
		var blockSize uint32
		if err := binary.Read(r, binary.LittleEndian, &blockSize); err != nil || blockSize == 0 {
			break
		}
		var sig uint32
		if err := binary.Read(r, binary.LittleEndian, &sig); err != nil {
			break
		}
		if sig == 0xA0000000 {
			break
		}
		if _, err := io.CopyN(io.Discard, r, int64(blockSize-8)); err != nil {
			break
		}
	}
}

func parseVolumeId(data []byte, offset uint32) {
	start := int(offset)
	if start+16 > len(data) {
		log.Printf("[WARNING] VolumeID structure too short at offset %d", offset)
		return
	}

	shellLink.LinkInfo.VolumeID.VolumeIdSize = binary.LittleEndian.Uint32(data[start : start+4])
	shellLink.LinkInfo.VolumeID.DriveType = binary.LittleEndian.Uint32(data[start+4 : start+8])
	shellLink.LinkInfo.VolumeID.DriveSerialNumber = binary.LittleEndian.Uint32(data[start+8 : start+12])
	shellLink.LinkInfo.VolumeID.VolumeLabelOffset = binary.LittleEndian.Uint32(data[start+12 : start+16])
	if shellLink.LinkInfo.VolumeID.VolumeLabelOffset == 20 {
		shellLink.LinkInfo.VolumeID.VolumeLabelOffsetUnicode = binary.LittleEndian.Uint32(data[start+16 : start+20])
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

func parseCommonNetworkRelativeLink(data []byte, offset uint32) {
	start := int(offset)
	link := &shellLink.LinkInfo.CommonNetworkRelativeLink

	link.CommonNetworkRelativeLinkSize = binary.LittleEndian.Uint32(data[start : start+4])
	if link.CommonNetworkRelativeLinkSize < 0x14 {
		log.Printf("[WARNING] Invalid CommonNetworkRelativeLinkSize: %d", link.CommonNetworkRelativeLinkSize)
		return
	}

	link.CommonNetworkRelativeLinkFlags = binary.LittleEndian.Uint32(data[start+4 : start+8])
	link.NetNameOffset = binary.LittleEndian.Uint32(data[start+8 : start+12])
	link.DeviceNameOffset = binary.LittleEndian.Uint32(data[start+12 : start+16])
	link.NetworkProviderType = binary.LittleEndian.Uint32(data[start+16 : start+20])

	if link.NetNameOffset != 0 {
		netNameStart := start + int(link.NetNameOffset)
		end := utils.FindNullTerminator(data[netNameStart:])
		link.NetName = data[netNameStart : netNameStart+end]
	}

	if link.CommonNetworkRelativeLinkFlags&0x1 != 0 && link.DeviceNameOffset != 0 {
		deviceStart := start + int(link.DeviceNameOffset)
		end := utils.FindNullTerminator(data[deviceStart:])
		link.DeviceName = data[deviceStart : deviceStart+end]
	}

	if link.CommonNetworkRelativeLinkFlags&0x2 == 0 {
		link.NetworkProviderType = 0
	}
}
