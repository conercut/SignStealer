import sys
import os
import shutil
import struct
import io

# Get info from PE Header
def gather_file_info_win(binary):
    """
    Borrowed from BDF...
    I could just skip to certLOC... *shrug*
    """
    flItms = {}
    binary = open(binary, 'rb')
    binary.seek(int('3C', 16))
    flItms['buffer'] = 0
    flItms['JMPtoCodeAddress'] = 0
    flItms['dis_frm_pehdrs_sectble'] = 248
    flItms['pe_header_location'] = struct.unpack('<i', binary.read(4))[0]
    flItms['COFF_Start'] = flItms['pe_header_location'] + 4
    binary.seek(flItms['COFF_Start'])
    flItms['MachineType'] = struct.unpack('<H', binary.read(2))[0]
    binary.seek(flItms['COFF_Start'] + 2, 0)
    flItms['NumberOfSections'] = struct.unpack('<H', binary.read(2))[0]
    flItms['TimeDateStamp'] = struct.unpack('<I', binary.read(4))[0]
    binary.seek(flItms['COFF_Start'] + 16, 0)
    flItms['SizeOfOptionalHeader'] = struct.unpack('<H', binary.read(2))[0]
    flItms['Characteristics'] = struct.unpack('<H', binary.read(2))[0]
    flItms['OptionalHeader_start'] = flItms['COFF_Start'] + 20

    binary.seek(flItms['OptionalHeader_start'])
    flItms['Magic'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MajorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
    flItms['MinorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
    flItms['SizeOfCode'] = struct.unpack("<I", binary.read(4))[0]
    flItms['SizeOfInitializedData'] = struct.unpack("<I", binary.read(4))[0]
    flItms['SizeOfUninitializedData'] = struct.unpack("<I",
                                                      binary.read(4))[0]
    flItms['AddressOfEntryPoint'] = struct.unpack('<I', binary.read(4))[0]
    flItms['PatchLocation'] = flItms['AddressOfEntryPoint']
    flItms['BaseOfCode'] = struct.unpack('<I', binary.read(4))[0]
    if flItms['Magic'] != 0x20B:
        flItms['BaseOfData'] = struct.unpack('<I', binary.read(4))[0]

    if flItms['Magic'] == 0x20B:
        flItms['ImageBase'] = struct.unpack('<Q', binary.read(8))[0]
    else:
        flItms['ImageBase'] = struct.unpack('<I', binary.read(4))[0]
    flItms['SectionAlignment'] = struct.unpack('<I', binary.read(4))[0]
    flItms['FileAlignment'] = struct.unpack('<I', binary.read(4))[0]
    flItms['MajorOperatingSystemVersion'] = struct.unpack('<H',
                                                          binary.read(2))[0]
    flItms['MinorOperatingSystemVersion'] = struct.unpack('<H',
                                                          binary.read(2))[0]
    flItms['MajorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MinorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MajorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MinorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['Win32VersionValue'] = struct.unpack('<I', binary.read(4))[0]
    flItms['SizeOfImageLoc'] = binary.tell()
    flItms['SizeOfImage'] = struct.unpack('<I', binary.read(4))[0]
    flItms['SizeOfHeaders'] = struct.unpack('<I', binary.read(4))[0]
    flItms['CheckSum'] = struct.unpack('<I', binary.read(4))[0]
    flItms['Subsystem'] = struct.unpack('<H', binary.read(2))[0]
    flItms['DllCharacteristics'] = struct.unpack('<H', binary.read(2))[0]
    if flItms['Magic'] == 0x20B:
        flItms['SizeOfStackReserve'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['SizeOfStackCommit'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['SizeOfHeapReserve'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['SizeOfHeapCommit'] = struct.unpack('<Q', binary.read(8))[0]

    else:
        flItms['SizeOfStackReserve'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfStackCommit'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfHeapReserve'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfHeapCommit'] = struct.unpack('<I', binary.read(4))[0]
    flItms['LoaderFlags'] = struct.unpack('<I', binary.read(4))[0]  # zero
    flItms['NumberofRvaAndSizes'] = struct.unpack('<I', binary.read(4))[0]

    flItms['ExportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ExportTableSize'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ImportTableLOCInPEOptHdrs'] = binary.tell()

    flItms['ImportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ImportTableSize'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ResourceTable'] = struct.unpack('<Q', binary.read(8))[0]
    flItms['ExceptionTable'] = struct.unpack('<Q', binary.read(8))[0]
    flItms['CertTableLOC'] = binary.tell()
    flItms['CertLOC'] = struct.unpack("<I", binary.read(4))[0]
    flItms['CertSize'] = struct.unpack("<I", binary.read(4))[0]
    binary.close()
    return flItms



# Copy Cert from signed PE
def copyCert(exe):
    flItms = gather_file_info_win(exe)

    if flItms['CertLOC'] == 0 or flItms['CertSize'] == 0:
        # Exit without signed
        sys.exit(-1)

    with open(exe, 'rb') as f:
        f.seek(flItms['CertLOC'], 0)
        cert = f.read(flItms['CertSize'])
    return cert

# Write the Cert into unsigned PE
def writeCert(cert, exe, output):
    flItms = gather_file_info_win(exe)

    if not output:
        output = str(exe) + "_signed"

    shutil.copy2(exe, output)

    with open(exe, 'rb') as g:
        with open(output, 'wb') as f:
            f.write(g.read())
            f.seek(0)
            f.seek(flItms['CertTableLOC'], 0)
            f.write(struct.pack("<I", len(open(exe, 'rb').read())))
            f.write(struct.pack("<I", len(cert)))
            f.seek(0, io.SEEK_END)
            f.write(cert)

if __name__ == '__main__':

    if len(sys.argv) != 4:
        print('Usage: python %s signed_exe unsigned_exe output_exe' % sys.argv[0])
        sys.exit(1)
    
    signed_exe = sys.argv[1]
    unsigned_exe = sys.argv[2] 
    output_exe = sys.argv[3]

    if not os.path.exists(signed_exe):
        print('Signed exe not found!')
        sys.exit(1)

    if not os.path.exists(unsigned_exe):
        print('Unsigned exe not found!')
        sys.exit(1)

    cert = copyCert(signed_exe)
    writeCert(cert, unsigned_exe, output_exe)

    print('Signed exe generated at:', output_exe)