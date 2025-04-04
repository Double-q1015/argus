import pefile
import os
import re
from datetime import datetime
import json
import pyimpfuzzy
from bz2 import compress
from pefile import PE, PEFormatError
from hashlib import sha256
from struct import pack
import math
import hashlib
import subprocess

PLATFORM_NAMES = {
    0x014C: "Intel 386 or later processors and compatible processors",
    0x0162: "MIPS little-endian, 0x160 big-endian",
    0x0166: "MIPS with FPU",
    0x0168: "MIPS16 with FPU",
    0x0169: "MIPS little-endian WCE v2",
    0x0184: "Alpha_AXP",
    0x01A2: "SH3 little-endian",
    0x01A3: "SH3 DSP",
    0x01A4: "SH3E little-endian",
    0x01A6: "SH4 little-endian",
    0x01A8: "SH5",
    0x01C0: "ARM Little-Endian",
    0x01C2: "ARM Thumb/Thumb-2 Little-Endian",
    0x01C4: "ARM Thumb-2 Little-Endian",
    0x01D3: "TAM33BD",
    0x01F0: "IBM PowerPC Little-Endian",
    0x01F1: "POWERPCFP",
    0x0200: "Intel 64",
    0x0266: "MIPS",
    0x0284: "ALPHA64 / AXP64",
    0x0366: "MIPS with FPU",
    0x0466: "MIPS16 with FPU",
    0x0520: "ARM64 Little-Endian",
    0x0CEF: "CEF",
    0x0EBC: "EFI Byte Code",
    0x8664: "AMD64 (K8)",
    0x9041: "M32R little-endian",
    0xAA64: "ARM64 Little-Endian",
    0xC0EE: "CEE"
}

def get_platform_name(platform_value):
    return PLATFORM_NAMES.get(platform_value, "Unknown Platform")

def get_richhash(file_path):
    # get richhash
    fh = open(file_path, "rb")
    content = fh.read()

    try:
        xorkey = re.search(b"\x52\x69\x63\x68....\x00", content).group(0)[4:8]
        dansAnchor = []

        for x, y in zip(xorkey, b"\x44\x61\x6e\x53"):
            xored = x ^ y
            dansAnchor.append(xored)
        dansAnchor = bytes(dansAnchor)

    except:
        return "", ""

    richStart = re.search(re.escape(dansAnchor), content).start(0)
    richEnd = re.search(b"\x52\x69\x63\x68" + re.escape(xorkey), content).start(0)

    if richStart < richEnd:
        rhData = content[richStart:richEnd]
    else:
        raise Exception("The Rich header is not properly formated!")

    clearData = []
    for i in range(0, len(rhData)):
        clearData.append(rhData[i] ^ xorkey[i % len(xorkey)])

    clearData = bytes(clearData)

    xored_richhash = hashlib.md5(rhData).hexdigest().lower()
    clear_richhash = hashlib.md5(clearData).hexdigest().lower()
    fh.close()

    return xored_richhash, clear_richhash
def get_version_info(pe):
    version_info = {}
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        ffi = pe.VS_FIXEDFILEINFO[0]
        version_info['FileDescription'] = ffi.FileDescription
        version_info['FileVersion'] = f"{ffi.FileVersionMS >> 16}.{ffi.FileVersionMS & 0xFFFF}.{ffi.FileVersionLS >> 16}.{ffi.FileVersionLS & 0xFFFF}"
        version_info['ProductName'] = ffi.ProductName
        version_info['ProductVersion'] = f"{ffi.ProductVersionMS >> 16}.{ffi.ProductVersionMS & 0xFFFF}.{ffi.ProductVersionLS >> 16}.{ffi.ProductVersionLS & 0xFFFF}"
        version_info['CompanyName'] = ffi.CompanyName
        version_info['LegalCopyright'] = ffi.LegalCopyright
        version_info['InternalName'] = ffi.InternalName
        version_info['OriginalFilename'] = ffi.OriginalFilename
        version_info['Comments'] = ffi.Comments
        version_info['Language'] = f"0x{ffi.Language:04X} 0x{ffi.CodePage:04X}"

    return version_info

def get_debug_info(pe):
    debug_info = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        for entry in pe.DIRECTORY_ENTRY_DEBUG:
            if entry.struct.Type == pefile.DEBUG_TYPE.PDB:
                pdb_path = entry.PDB_Path
                if isinstance(pdb_path, bytes):
                    pdb_path = pdb_path.decode('utf-8', errors='ignore').strip('\x00')
                debug_info['PDB'] = pdb_path
                debug_info['GUID'] = entry.guid
    return debug_info

def calculate_entropy(data):
    if not data:
        return 0
    if isinstance(data, str):
        data = data.encode('utf-8')
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def calculate_md5(data):
    return hashlib.md5(data).hexdigest()

def get_section_info(pe):
    section_info = []
    for section in pe.sections:
        section_name = section.Name
        if isinstance(section_name, bytes):
            section_name = section_name.decode('utf-8').rstrip('\x00')
        
        section_data = section.get_data()
        section_info.append({
            'Name': section_name,
            'VirtualAddress': hex(section.VirtualAddress),
            'VirtualSize': hex(section.Misc_VirtualSize),
            'RawAddress': hex(section.PointerToRawData),
            'RawSize': hex(section.SizeOfRawData),
            'Permissions': 'R-E' if section.Characteristics & 0x20000000 else 'R--',
            'Entropy': calculate_entropy(section_data),
            'Hash': calculate_md5(section_data)
        })
    return section_info

def get_pehashng(pe) ->str:
    """ Return pehashng for PE file, sha256 of PE structural properties.

    :param pe_file: file name or instance of pefile.PE() class
    :return: SHA256 in hexdigest format, None in case of pefile.PE() error
    :rtype: str
    """
    data_sha256 = ""
    try:
        if isinstance(pe, PE):
            exe = pe
        else:
            raise TypeError("Error getting pshashng info: Invalid PE object")
        def align_down_p2(number):
            return 1 << (number.bit_length() - 1) if number else 0

        def align_up(number, boundary_p2):
            assert not boundary_p2 & (boundary_p2 - 1), \
                "Boundary '%d' is not a power of 2" % boundary_p2
            boundary_p2 -= 1
            return (number + boundary_p2) & ~ boundary_p2

        def get_dirs_status():
            dirs_status = 0
            for idx in range(min(exe.OPTIONAL_HEADER.NumberOfRvaAndSizes, 16)):
                if exe.OPTIONAL_HEADER.DATA_DIRECTORY[idx].VirtualAddress:
                    dirs_status |= (1 << idx)
            return dirs_status

        def get_complexity():
            complexity = 0
            if section.SizeOfRawData:
                complexity = (len(compress(section.get_data())) *
                            7.0 /
                            section.SizeOfRawData)
                complexity = 8 if complexity > 7 else int(round(complexity))
            return complexity

        characteristics_mask = 0b0111111100100011
        data_directory_mask = 0b0111111001111111

        data = [
            pack('> H', exe.FILE_HEADER.Characteristics & characteristics_mask),
            pack('> H', exe.OPTIONAL_HEADER.Subsystem),
            pack("> I", align_down_p2(exe.OPTIONAL_HEADER.SectionAlignment)),
            pack("> I", align_down_p2(exe.OPTIONAL_HEADER.FileAlignment)),
            pack("> Q", align_up(exe.OPTIONAL_HEADER.SizeOfStackCommit, 4096)),
            pack("> Q", align_up(exe.OPTIONAL_HEADER.SizeOfHeapCommit, 4096)),
            pack('> H', get_dirs_status() & data_directory_mask)]

        for section in exe.sections:
            data += [
                pack('> I', align_up(section.VirtualAddress, 512)),
                pack('> I', align_up(section.SizeOfRawData, 512)),
                pack('> B', section.Characteristics >> 24),
                pack("> B", get_complexity())]

        if not isinstance(pe, PE):
            exe.close()
        data_sha256 = sha256(b"".join(data)).hexdigest()
    except Exception as e:
        data_sha256 = ""
        raise ValueError(f"Error getting pshashng info: {e}")
    finally:
        return data_sha256
def get_pe_info(pe_file_path):
    if not os.path.exists(pe_file_path):
        raise FileNotFoundError(f"The file {pe_file_path} does not exist.")
    
    try:
        pe = pefile.PE(pe_file_path)
    except pefile.PEFormatError as e:
        raise ValueError(f"Error parsing the PE file {pe_file_path}: {e}")

    # 获取PE头信息
    platform_value = pe.FILE_HEADER.Machine
    pe_header_info = {
        'platform': hex(platform_value),
        'platform_name': get_platform_name(platform_value),
        'time_datestamp': pe.FILE_HEADER.TimeDateStamp,
        'entrypoint': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
        'number_of_sections': pe.FILE_HEADER.NumberOfSections,
        'linkerversion': (pe.OPTIONAL_HEADER.MajorLinkerVersion, pe.OPTIONAL_HEADER.MinorLinkerVersion)
    }
    # 将 TimeDateStamp 转换为 datetime
    pe_header_info['time_datetime_utc'] = datetime.utcfromtimestamp(pe_header_info['time_datestamp']).strftime('%Y-%m-%d %H:%M:%S')

    # 调试信息
    # debug_info = get_debug_info(pe)

    # 获取richhash
    xored_richhash, clear_richhash = get_richhash(pe_file_path)
    print(xored_richhash, clear_richhash)

    # 获取 pehashng
    pehashng = get_pehashng(pe)

    # 获取版本信息
    version_info = get_version_info(pe)

    # 获取节区信息
    section_info = get_section_info(pe)

    # 获取签名信息
    signature_info = "Not Signed"
    if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
        signature_info = "Signed"

    # 获取导入表信息
    import_table_info = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            for imp in entry.imports:
                func_name = imp.name.decode('utf-8') if imp.name else f"Ordinal {imp.ordinal}"
                func_address = hex(imp.address)
                import_table_info.append({
                    'DLL': dll_name,
                    'FunctionName': func_name,
                    'FunctionAddress': func_address
                })

    # 获取资源节信息
    resource_info = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
                resource_name = resource_type.name
            else:
                resource_name = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, hex(resource_type.struct.Id))
            
            for resource_id in resource_type.directory.entries:
                if resource_id.name is not None:
                    resource_id_name = resource_id.name
                else:
                    resource_id_name = hex(resource_id.struct.Id)
                
                for resource_lang in resource_id.directory.entries:
                    resource_info.append({
                        'Type': resource_name,
                        'ID': resource_id_name,
                        'Language': hex(resource_lang.data.lang),
                        'SubLanguage': hex(resource_lang.data.sublang),
                        'Size': hex(resource_lang.data.struct.Size),
                        'Offset': hex(resource_lang.data.struct.OffsetToData)
                    })

    # 组合所有信息到一个字典
    pe_info = {
        'PEHeaderInfo': pe_header_info,
        'VersionInfo': version_info,
        # 'DebugInfo': debug_info,
        'pehashng': pehashng,
        # 'SectionInfo': section_info,
        # 'SignatureInfo': signature_info,
        # 'ImportTableInfo': import_table_info,
        # 'ResourceInfo': resource_info
    }

    return pe_info

# 示例调用
if __name__ == "__main__":
    pe_file_path = "/data/004ad8ce84b9ab95d4c38a9d7b23dce68d134c696c1362625ad38153b48038e5"
    try:
        pe_info = get_pe_info(pe_file_path)
        print(json.dumps(pe_info, indent=4))
    except Exception as e:
        print(f"An error occurred: {e}")