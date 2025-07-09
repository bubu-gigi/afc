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
    linkFlags          	map[string]bool
	fileAttributesFlags map[string]bool
	hotKeyLowByte      	string
	hotKeyHighByte      string
	parsedItems 		[]string
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
		"LocalBasePath", "CommonPathSuffix", "VolumeLabel", "DriveType", "DriveSerialNumber", "ItemIdListReadable",
		"NetName", "DeviceName", "NetworkProviderType", "CommonNetworkRelativeLinkFlags",
	}
	writer.Write(headers)
	writer.UseCRLF = true

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
	utils.CheckShowCommand(&shellLink.Header.ShowCommand)
	shellLink.Header.HotKey = binary.LittleEndian.Uint16(header[64:66])
	shellLink.Header.Reserved1 = binary.LittleEndian.Uint16(header[66:68])
	utils.CheckNullUint16(shellLink.Header.Reserved1)
	shellLink.Header.Reserved2 = binary.LittleEndian.Uint32(header[68:72])
	utils.CheckNullUint32(shellLink.Header.Reserved2)
	shellLink.Header.Reserved3 = binary.LittleEndian.Uint32(header[72:76])
	utils.CheckNullUint32(shellLink.Header.Reserved3)
	//populate flags and hotKeys
	linkFlags = utils.ParseLinkFlags(shellLink.Header.LinkFlags)
	fileAttributesFlags = utils.ParseFileAttributesFlags(shellLink.Header.FileAttributes)
	hotKeyLowByte = utils.ParseHotKeyLowByte(header[64])
	hotKeyHighByte = utils.ParseHotKeyHighByte(header[65])
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

func parseItemIdToString(item ItemId) string {
	str := string(item.Data)
	if utils.IsPrintable(str) {
		return str
	}
	return fmt.Sprintf("% X", item.Data)
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
		parsedItems = append(parsedItems, parseItemIdToString(item))
		offset += int(itemSize)
	}

	shellLink.LinkTargetIdList.ItemIdList = items 
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

func parseCommonNetworkRelativeLink(data []byte, offset uint32) {
	start := int(offset)
	link := &shellLink.LinkInfo.CommonNetworkRelativeLink

	link.CommonNetworkRelativeLinkSize = binary.LittleEndian.Uint32(data[start:start+4])
	if shellLink.LinkInfo.CommonNetworkRelativeLink.CommonNetworkRelativeLinkSize < 0x00000014 {
		fmt.Println("Error: the CommonNetworkRelativeLinkSize must be at least 20")
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
