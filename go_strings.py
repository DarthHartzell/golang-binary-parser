"""
Author: Alexander Hanel
Version: 1.0
Purpose: go portable executable parser
Requirements: Python3+ & elf file

"""
import argparse
import re
import elftools
import elftools.elf
import elftools.elf.elffile
import pefile
import struct
import ctypes
import glob
import binascii
import json
from hashlib import md5
from difflib import SequenceMatcher
from module_data import *
from poor_cluster_logic import *
from capstone import *
import pprint

IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_AMD64 = 0x8664

ELFMAGIC = b'\x7f\x45\x4c\x46'
WINMAGIC = b'\x4d\x5a'

ELFTYPE = 0x45
WINTYPE = 0x4d

# Go Version Constants
VERSION_1_16 = b"\x67\x6f\x31\x2e\x31\x36"
VERSION_1_15 = b"\x67\x6f\x31\x2e\x31\x35"
VERSION_1_14 = b"\x67\x6f\x31\x2e\x31\x34"
VERSION_1_13 = b"\x67\x6f\x31\x2e\x31\x33"
VERSION_1_12 = b"\x67\x6f\x31\x2e\x31\x32"
VERSION_1_11 = b"\x67\x6f\x31\x2e\x31\x31"
VERSION_1_10 = b"\x67\x6f\x31\x2e\x31\x30"
VERSION_1_9 = b"\x67\x6f\x31\x2e\x39"
VERSION_1_8 = b"\x67\x6f\x31\x2e\x38"
VERSION_1_7 = b"\x67\x6f\x31\x2e\x37"
VERSION_1_6 = b"\x67\x6f\x31\x2e\x36"
VERSION_1_5 = b"\x67\x6f\x31\x2e\x35"
VERSION_1_4 = b"\x67\x6f\x31\x2e\x34"
VERSION_1_3 = b"\x67\x6f\x31\x2e\x33"
VERSION_1_2 = b"\x67\x6f\x31\x2e\x32"

# Go Magic PCIntab
G012MAGIC = b"\xFB\xFF\xFF\xFF\x00\x00"
GO1XMAGIC = b"\xFF\xFF\xFF\xFB\x00\x00"

def check_string(s):
    for c in s:
        if c < 0x20 or c > 0x7e:
            return False
    return True

class GOEXE(object):
    def __init__(self, file_path, debug=False):
        self.file_path = file_path
        self.debug = debug
        self.annoying_debug = False
        self.error = False
        self.error_message = None
        self.go_version = None
        self.f = None
        self.elf = None
        self.pe = None
        self.bit = None
        self.size = None
        self.text = None
        self.data = None
        self.raw = None
        self.rodata = None
        self.text_start = 0
        self.text_end = 0
        self.data_start = 0
        self.data_end = 0
        self.rodata_start = 0
        self.rodata_end = 0
        self.go_base_paths = None
        self.gopclntab = None
        self.gopclntab_start = None
        self.gopclntab_end = None
        self.functab = None
        self.filetab = []
        self.itab_sym = []
        self.static_strings = []
        self.dynamic_strings = []
        self.mod_section = None  # section that contains the
        self.module_data = None
        self.hash_sys_all = None
        self.hash_sys_main = None
        self.hash_sys_nomain = None
        self.hash_itabs = None
        self.function_main = None
        self.hash_file_paths = None
        self.stripped = None
        self.packed = False
        self.pcln_section = None
        self.symbols = []
        self.symtab_symbols = [] # function names, symbols needed
        self.file_type = 0
        self.load_exe()
        if not self.error:
            self.exe_bit()
            self.parse()
            # self.is_stripped()
            # self.is_packed()

    def get_version_by_string(self, data):
        """
        :param data:
        :return:
        """
        # for section in self.elf.iter_sections():
        #     data = section.data()
        if VERSION_1_16 in data:
            return 'Go 1.16'
        if VERSION_1_15 in data:
            return 'Go 1.15'
        if VERSION_1_14 in data:
            return 'Go 1.14'
        if VERSION_1_13 in data:
            return 'Go 1.13'
        if VERSION_1_12 in data:
            return 'Go 1.12'
        if VERSION_1_11 in data:
            return 'Go 1.11'
        if VERSION_1_10 in data:
            return 'Go 1.10'
        if VERSION_1_9 in data:
            return 'Go 1.9'
        if VERSION_1_8 in data:
            return 'Go 1.8'
        if VERSION_1_7 in data:
            return 'Go 1.7'
        if VERSION_1_6 in data:
            return 'Go 1.6'
        if VERSION_1_5 in data:
            return 'Go 1.5'
        if VERSION_1_4 in data:
            return 'Go 1.4'
        if VERSION_1_3 in data:
            return 'Go 1.3'
        if VERSION_1_2 in data:
            return 'Go 1.2'
        return None

    def parse(self):
        if self.file_type == ELFTYPE:
            self.text = self.elf.get_section_by_name('.text')
            self.data = self.elf.get_section_by_name('.data')
            self.rodata = self.elf.get_section_by_name('.rodata')
            self.gopclntab = self.elf.get_section_by_name('.gopclntab')
            self.rodata_start = self.rodata.header.sh_addr
            self.rodata_end = self.rodata_start + self.rodata.header.sh_size
            self.data_start = self.data.header.sh_offset
            self.data_end = self.data_start + self.data.header.sh_size
            self.text_start = self.text.header.sh_addr
            self.text_end = self.text_start + self.text.header.sh_size
            self.gopclntab_start = self.gopclntab.header.sh_addr
            self.gopclntab_end = self.text_start + self.gopclntab.header.sh_size
            self.rodata = self.rodata.data()
            self.text = self.text.data()
            self.data = self.data.data()
            self.gopclntab = self.gopclntab.data()
            for section in self.elf.iter_sections():
                data = section.data()
                self.go_version = self.get_version_by_string(data)
                if self.go_version is not None:
                    break
            #self.mod_section = self.gopclntab
        else:
            for section in self.pe.sections:
                data = section.get_data()
                if self.go_version is None:
                    self.go_version = self.get_version_by_string(data)
                if b'.text' in section.Name:
                    self.text = section.get_data()
                    self.text_start = section.VirtualAddress + self.pe.OPTIONAL_HEADER.ImageBase
                    self.text_end = section.next_section_virtual_address + self.pe.OPTIONAL_HEADER.ImageBase
                elif b'.data' in section.Name:
                    self.data = section.get_data()
                    self.data_start = section.VirtualAddress + self.pe.OPTIONAL_HEADER.ImageBase
                    self.data_end = section.next_section_virtual_address + self.pe.OPTIONAL_HEADER.ImageBase
                elif b'.rdata' in section.Name:
                    self.rodata = section.get_data()
                    self.rodata_start = section.VirtualAddress + self.pe.OPTIONAL_HEADER.ImageBase
                    self.rodata_end = section.next_section_virtual_address + self.pe.OPTIONAL_HEADER.ImageBase
                if self.text != None and self.data != None and self.rodata != None and self.go_version != None:
                    break
        
        self.gopclntab_offset, section_va = self.find_go_pc_ln()
        va_offset = section_va
        xref_pattern = self.pack_me(va_offset)
        md_offset, md_va_offset = self.find_module_data(xref_pattern)
        self.parse_module_data(md_offset)
        # self.parse_file_tab()

    # elftools requires the file to remain open to do things such as iterate
    def __del__(self):
        if self.f is not None:
            self.f.close()

    def load_exe(self):
        """
        parse portable executable using Pefile.
        :return:
        """
        try:
            with open(self.file_path, 'rb') as raw_file:
                self.raw = raw_file.read()

            # determine if ELF or WIN
            if ELFMAGIC == self.raw[:len(ELFMAGIC)]:
                self.file_type = ELFTYPE
                self.f = open(self.file_path, 'rb')
                self.elf = elftools.elf.elffile.ELFFile(self.f)
                print('elf file')
            else:
                self.file_type = WINTYPE
                self.pe = pefile.PE(self.file_path)
                print('pe file')            
            
        except Exception as e:
            self.error = True
            self.error_message = e

    def is_packed(self):
        """super simple "packer" checks for a string in the section name"""
        pattern = b"UPX executable"
        regex = re.compile(pattern)
        if re.search(regex, self.raw):
            self.packed = True
            if self.debug:
                print("DEBUG: Sample is packed")
            return

    def exe_bit(self):
        """
        detect bit
        :return:
        """
        if ((self.file_type == ELFTYPE and 
             self.elf.elfclass == 32)
             or (self.file_type == WINTYPE and 
             self.pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_I386)):
                self.bit = 32
                self.size = 4
                if self.debug:
                    print("DEBUG: Bit 32, size 4")
        else:
            self.bit = 64
            self.size = 8
            if self.debug:
                print("DEBUG: Bit 64, size 8")

    def ptr(self, addr, size=None):
        """
        read data at given offset, size can be modified because 64bit exes can still use 32bit sizes (4bytes)
        parses a particular section because some structures
        :param addr:
        :param size:
        :return:
        """
        if not size:
            size = self.size
        if size == 4:
            data = self.pcln_section[addr:addr + size]
            return struct.unpack("<I", data)[0]
        else:
            data = self.pcln_section[addr:addr + size]
            if len(data) < 8:
                data = b'\x00\x00\x00\x00\x00\x00\x00\x00'
            return struct.unpack("<Q", data)[0]

    def file_ptr(self, addr, size=None):
        """
        read data at given offset, size can be modified because 64bit exes can still use 32bit sizes (4bytes)
        :param addr:
        :param size:
        :return:
        """
        if not size:
            size = self.size
        if size == 4:
            data = self.raw[addr:addr + size]
            return struct.unpack("<I", data)[0]
        else:
            data = self.raw[addr:addr + size]
            return struct.unpack("<Q", data)[0]

    def pack_me(self, ii):
        if self.size == 4:
            return struct.pack("<I", ii)
        else:
            return struct.pack("<Q", ii)

    # virtual address to file offset
    def rva2file(self, offset):
        for section in self.elf.iter_sections():
            if section.header.sh_addr <= offset < section.header.sh_addr + section.header.sh_size:
                return offset - section.header.sh_addr + section.header.sh_offset

    # file offset to virtual address
    def file2va(self, offset):
        for section in self.elf.iter_sections():
            if section.header.sh_offset < offset < section.header.sh_offset + section.header.sh_size:
                return section.header.sh_addr + (section.header.sh_offset - offset)

    def check_is_gopclntab(self, addr):
        """
        TODO: Check header: 4-byte magic, two zeros, pc quantum, pointer size.
              https://github.com/golang/go/blob/52fe92fbaa41a6441144029760ada24b5be1d398/src/debug/gosym/pclntab.go
        :param addr:
        :return:
        """
        first_entry = self.ptr(addr + 8 + self.size)
        if self.debug:
            print("DEBUG: First sec offset is 0x%x" % first_entry)
        first_entry_off = self.ptr(addr + 8 + self.size * 2)
        if self.debug:
            print("DEBUG: First Entry offset is 0x%x" % first_entry_off)
        addr_func = addr + first_entry_off
        if self.debug:
            print("DEBUG: Addr Func offset is 0x%x" % addr_func)
        func_loc = self.ptr(addr_func)
        if self.debug:
            print("DEBUG: Addr Func Loc offset is 0x%x" % func_loc)
        if func_loc == first_entry:
            return True
        return False

    def find_go_pc_ln(self):
        """
        :return:
        """
        lookup = [G012MAGIC, GO1XMAGIC]
        for pattern in lookup:
            if self.elf != None:
                for section in self.elf.iter_sections():
                    section_data = section.data()
                    offset = section_data.find(pattern)
                    if offset == -1:
                        continue
                    else:
                        self.pcln_section = section.data()
                        if self.debug:
                            sec_name = section.name
                            print("DEBUG: gopclntab offset is 0x%x in section %s at file offset 0x%x" % (offset, sec_name, offset + section.header.sh_offset))
                        if self.check_is_gopclntab(offset):
                            return section.header.sh_offset, section.header.sh_addr
            else:
                for cc, section in enumerate(self.pe.sections):
                    section_data = self.pe.sections[cc].get_data()
                    offset = section_data.find(pattern)
                    if offset == -1:
                        continue
                    else:
#                        self.pe_section = self.pe.sections[cc].get_data()
                        self.pcln_section = self.pe.sections[cc].get_data()
                        if self.debug:
                            sec_name = section.Name.decode("utf-8").replace("\x00","")
                            print("DEBUG: gopclntab offset is 0x%x in section %s at file offset 0x%x" % (offset, sec_name, offset + section.PointerToRawData))
                        if self.check_is_gopclntab(offset):
                            return offset, section.VirtualAddress
        return None, None

    def find_module_data(self, pattern):
        """
        :param pattern:
        :return:
        """
        if self.debug:
            print("DEBUG: xref pattern %s" % binascii.hexlify(pattern))
        if self.elf != None:
            for section in self.elf.iter_sections():
                section_data = section.data()
                offset = section_data.find(pattern)
                if offset != -1:
                    self.mod_section = section_data
                    return offset, offset + section.header.sh_addr
        else:
            for cc, section in enumerate(self.pe.sections):
                section_data = self.pe.sections[cc].get_data()
                offset = section_data.find(pattern)
                if offset != -1:
                    self.mod_section = section_data
                    return offset, offset + section.VirtualAddress
        if self.debug:
            print("DEBUG: xref pattern %s not found" % binascii.hexlify(pattern))
        return None, None

    def parse_module_data(self, offset):
        """

        :param offset:
        :return:
        """
        # TODO add module data for older versions
        if self.go_version in ['Go 1.10', 'Go 1.11', 'Go 1.12', 'Go 1.13', 'Go 1.14', 'Go 1.15']:
            if self.bit == 32:
                self.module_data = ModuleDataGo1_10_15_32.from_buffer_copy(self.mod_section[offset:])
            else:
                self.module_data = ModuleDataGo1_10_15_64.from_buffer_copy(self.mod_section[offset:])

    def parse_file_tab(self):
        # filetab virtual adddress and length is stored within the Module Data
        # .data:00000000007C19E0                 dq offset unk_1C470F0   ; filetab.array
        # .data:00000000007C19E0                 dq 25Fh                 ; filetab.len
        # .data:00000000007C19E0                 dq 25Fh                 ; filetab.cap

        # verify the filetab values have been parsec from Module Data structure
        try:
            file_tab_len = self.module_data.filetab_len
        except:
            return
        # loop through each entry in the filetab
        # skip the first entry because its the size/length
        # the offset to the string is
        # 1. read offset at filetab[index] aka
        # 2. offset + gopclntab = offset to string
        for c in range(1, file_tab_len):
            offset = self.module_data.filetab + (c*4)
            # convert filetab to offset
            file_tab_offset = self.rva2file(offset)
            index = self.file_ptr(file_tab_offset, size=4)
            file_tab_str_offset = index + self.rva2file(self.module_data.pclntable)
            temp_string = self.raw[file_tab_str_offset:].split(b"\x00")[0]
            if temp_string:
                self.filetab.append(temp_string)

    def parse_itabsym(self):
        """
        itab, information runtime in table
        :return:
        """
        if self.stripped:
            return
        strtab = []
        for section in self.elf.iter_sections():
            if '.strtab' in section.name:
                strtab = section.data()
                break
        for section in self.elf.iter_sections():
            if ".symtab" in section.name:
                symbols_strings = []
                symtab = section.data()

                end_symbols = (section.header['sh_size'] // section.header['sh_entsize']) * 0x18
                string_table = strtab

                # read 18 bytes at a time until string table
                for ci in range(0, end_symbols, 0x18):
                    sym_data = symtab[ci:ci+0x18]
                    if not sym_data:
                        continue
                    p_data = self.parse_symbol_table(sym_data)
                    temp_data = string_table[p_data.st_name:p_data.st_name+256]
                    api_name = temp_data.split(b"\x00")[0]
                    if api_name:
                        symbols_strings.append(api_name)
                self.symtab_symbols = symbols_strings

    def parse_symbol_table(self, data):
        """
            typedef struct {
                uint32_t		st_name;
                uint8_t			st_info;
                uint8_t			st_other;
                uint16_t		st_shndx;
                uint64_t		st_value;
                uint64_t		st_size;
            } Elf32_Sym;
        """

        class Elf64_Sym(ctypes.Structure):
            _pack_ = 1
            _fields_ = [
                ("st_name", ctypes.c_uint), ("st_info", ctypes.c_ubyte), ("st_other", ctypes.c_ubyte),
                ("st_shndx", ctypes.c_ushort), ("st_value", ctypes.c_ulonglong),
                ("st_size", ctypes.c_ulonglong)
            ]
        cc = Elf64_Sym.from_buffer_copy(data)
        return cc
    
    def parse_static_strings(self):
        # this is the offset into the raw bytes of the file
        # ro_start = self.rodata.header.sh_addr
        # ro_size = self.rodata.header.sh_size
        # ro_end = ro_start + ro_size
        # ro_raw = self.rodata.data()
        # data_start = self.data.header.sh_offset
        # data_size = self.data.header.sh_size
        # data_end = data_start + data_size
        for i in range(self.data_start, self.data_end, 16):
            addr = self.file_ptr(i)
            if self.rodata_start < addr and addr < self.rodata_end:
                str_len = self.file_ptr(i+8)
                if str_len < 256 and str_len > 0:
                    s = self.rodata[addr-self.rodata_start:addr-self.rodata_start+str_len]
                    if check_string(s):
                        self.static_strings.append(s)

    def parse_dynamic_strings(self):
        # ro_start = self.rodata.header.sh_addr
        # ro_size = self.rodata.header.sh_size
        # ro_end = ro_start + ro_size
        # ro_raw = self.rodata.data()
        # ops = self.text.data()
        # addr = self.text['sh_addr']
        # textEnd = self.text['sh_size'] + addr
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.skipdata = True
        inst1 = inst2 = inst3 = None
        regex = re.compile("0x[0-9a-f]+")
        strPtr = 0

        for i in md.disasm(self.text, self.text_start):

            if i.mnemonic != 'lea' and i.mnemonic != 'mov':
                continue

            if inst1 == None:
                if i.mnemonic == 'lea':
                    rip = i.address
                    opStr = i.op_str.split(',')[1]
                    match = regex.findall(opStr)
                    if match == []:
                        continue
                    strPtr = rip+int(match[0],16)
                    if strPtr < self.text_end:
                        continue
                    # print("%x" % (strPtr))
                    inst1 = i
            elif inst2 == None:
                if i.mnemonic == 'mov':
                    opStr = i.op_str.split(', ')
                    if 'rsp' not in opStr[0] or 'rax' not in opStr[1]:
                        inst1 = None
                        continue
                    inst2 = i
                else:
                    inst1 = None
                    strPtr = 0
            elif inst3 == None:
                if i.mnemonic == 'mov':
                    opStr = i.op_str.split(',')[1]
                    match = regex.findall(opStr)
                    if match == []:
                        inst1 = inst2 = None
                        continue
                    strLength = int(match[0], 16)
                    if self.rodata_start < strPtr and strPtr < self.rodata_end:
                        if strLength < 256 and strLength > 0:
                            s = self.rodata[strPtr-self.rodata_start:strPtr-self.rodata_start+strLength]
                            if check_string(s):
                                self.dynamic_strings.append(s)
                    inst3 = i
                else:
                    inst1 = inst2 = None
                    strPtr = 0
            if inst3 != None:
                strPtr = 0
                inst1 = inst2 = inst3 = None

    def export(self):
        ee = {}
        if self.static_strings:
            ee["static_strings"] = self.static_strings
        if self.dynamic_strings:
            ee["dynamic_strings"] = self.dynamic_strings
        return ee

def decode_bytes(o):
    return o.decode('utf-8')

def save_json(ff, export):
    """
    :param ff: file path
    :param export: data
    :return:
    """
    if not ff:
        return
    try:
        with open(ff + ".json", "w") as tt_file:
            json.dump(export, tt_file, default=decode_bytes, indent=4, sort_keys=True)
    except Exception as e:
        print("ERROR: %s Exporting %s" % (e, ff))

def get_source_filenames(file_path):
    gp = GOEXE(file_path)

def find_static_strings(file_path):
    gp = GOEXE(file_path)
    gp.parse_static_strings()
    ee = gp.export()
    if gp.debug and ee:
        pprint.pprint(ee)

def find_dynamic_strings(file_path):
    gp = GOEXE(file_path)
    gp.parse_dynamic_strings()
    ee = gp.export()
    if gp.debug and ee:
        pprint.pprint(ee)

def find_all_strings(file_path):
    gp = GOEXE(file_path)
    gp.parse_static_strings()
    gp.parse_dynamic_strings()
    ee = gp.export()
    if gp.debug and ee:
        pprint.pprint(ee)
    print('found %d static strings' % (len(gp.static_strings)))
    print('found %d dynamic strings' % (len(gp.dynamic_strings)))
    setA = set(gp.static_strings)
    setB = set(gp.dynamic_strings)
    print('found %d static strings set' % (len(setA)))
    print('found %d dynamic strings set' % (len(setB)))
    overlap = setA & setB
    universe = setA | setB
    print('overlap len=%d universe len=%d' % (len(overlap), len(universe)))
    result1 = float(len(overlap)) / len(setA) * 100
    result2 = float(len(overlap)) / len(setB) * 100
    result3 = float(len(overlap)) / len(universe) * 100
    print('result1=%f result2=%f result3=%f' % (result1, result2, result3))

def compare_files(lhs, rhs):
    left_file = GOEXE(lhs)
    right_file = GOEXE(rhs)
    left_file.parse_static_strings()
    left_file.parse_dynamic_strings()
    right_file.parse_static_strings()
    right_file.parse_dynamic_strings()
    setA = set(set(left_file.static_strings) | set(left_file.dynamic_strings) )
    setB = set(set(right_file.static_strings) | set(right_file.dynamic_strings) )
    print('found %d strings in %s' % (len(setA), lhs))
    print('found %d strings in %s' % (len(setB), rhs))
    overlap = setA & setB
    universe = setA | setB
    print('overlap len=%d universe len=%d' % (len(overlap), len(universe)))
    result1 = float(len(overlap)) / len(setA) * 100
    result2 = float(len(overlap)) / len(setB) * 100
    result3 = float(len(overlap)) / len(universe) * 100
    print('overlap/lhs=%f overlap/rhs=%f overlap/universe=%f' % (result1, result2, result3))

def main():
    """
    :return:
    """
    cmd_p = argparse.ArgumentParser(description='gopep Go Elf String Finder')
    cmd_p.add_argument('-t', '--static', dest="s_file",
        help="find static strings in golang compiled binary")
    cmd_p.add_argument('-d', '--dynamic', dest="d_file",
        help="find dynamic strings in golang compiled binary")
    cmd_p.add_argument('-a', '--all', dest="a_file",
        help="find all strings in a golang compiled binary")
    cmd_p.add_argument('-c', '--compare', action='store_true',
        help="compare two golang compiled binaries")
    cmd_p.add_argument('-f', '--first', dest="f_file",
        help="first file to use in comparison")
    cmd_p.add_argument('-o', '--other', dest="o_file",
        help="other file to use in comparison")

    args = cmd_p.parse_args()
    if args.s_file:
        find_dynamic_strings(args.s_file)
        find_static_strings(args.s_file)
    elif args.d_file:
        find_dynamic_strings(args.d_file)
    elif args.a_file:
        find_all_strings(args.a_file)
    elif args.compare and args.f_file and args.o_file:
        compare_files(args.f_file, args.o_file)

if __name__ == "__main__":
    main()
