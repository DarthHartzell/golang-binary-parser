
import struct
from byte_reader import ByteReader

kinds =  [ "Invalid", "Bool", "Int", "Int8", "Int16", "Int32", "Int64",
           "Uint", "Uint8", "Uint16", "Uint32", "Uint64", "Uintptr",
           "Float32", "Float64", "Complex64", "Complex128", "Array",
           "Chan", "Func", "Interface", "Map", "Ptr", "Slice", "String",
           "Struct", "UnsafePointer" ]

class TypeMethods(object):
    def __init__(self):
        self.name = None
        self.type = 0
        self.iface_call_offset = 0
        self.func_call_offset = 0

class Go_Types(object):
    def __init__(self):
        self.name = None
        self.flag = 0
        self.kind = 0
        self.addr = 0
        self.ptr_resolv_addr = 0
        self.element = 0
        self.package_path = ""
        self.field_tag = None
        self.field_anon = 0
        self.fields = []
        self.is_variadic = 0
        self.func_args = []
        self.func_ret_vals = []
        self.methods = []
        self.length = 0
        self.chan_dir = 0

    def typeParse( self, types, offset, section_data, section_base_addr ):
        if (offset + section_base_addr) in types.keys():
            typ = types[offset+section_base_addr]
            return typ

        typ = Go_Types()
        if offset > len(section_data):
            return None
        r = ByteReader(section_data[offset:])

        # parse size
        size = r.read_64()

        # parse kind
        off = 23
        r.seek( off, r.SEEK_START )
        typ.kind = r.read_8() & ((1<<5)-1)

        # parse flag
        off = 20
        r.seek( off, r.SEEK_START )
        typ.flag = r.read_8()

        # parse nameOff
        off = 40
        r.seek( off, r.SEEK_START )
        n = r.read_32()
        typ.name = self.resolve_name( section_data, n, typ.flag )

        typ.addr = offset + section_base_addr
        types[typ.addr] = typ

        # parse extra fields
        off = 48
        r.seek( off, r.SEEK_START )
        if kinds[typ.kind] == "Ptr":
            ptr = r.read_64()
            self.ptr_resolv_addr = ptr
            if self.ptr_resolv_addr is not 0:
                c = self.typeParse(types, ptr-section_base_addr, section_data, section_base_addr)
                typ.element = c
            if typ.flag & 1:
                # parse uncommon types
                self.parse_uncommon_type( typ, r, section_data, section_base_addr, types )
        elif kinds[typ.kind] == "Slice":
            element_addr = r.read_64()
            if element_addr != 0:
                e = self.typeParse(types, element_addr-section_base_addr, section_data, section_base_addr)
                typ.element = e
            if typ.flag & 1:
                self.parse_uncommon_type( typ, r, section_data, section_base_addr, types )
            print("")
        elif kinds[typ.kind] == "Struct":
            pkg_name_ptr = r.read_64()
            if pkg_name_ptr != 0:
                n = self.resolve_name(section_data, pkg_name_ptr-section_base_addr, 0)
                typ.package_path = n
            field_ptr = r.read_64()
            num_field = r.read_64()
            # skip cap
            r.seek( 8, r.SEEK_CURRENT )
            # parse methods
            if typ.flag & 1:
                # parse uncommon types
                self.parse_uncommon_type( typ, r, section_data, section_base_addr, types )
            # parse fields
            sec_r = ByteReader(section_data)
            for i in range( num_field ):
                o = field_ptr + (i * 3 * 8) - section_base_addr
                sec_r.seek(o, sec_r.SEEK_START)
                nptr = sec_r.read_64()
                t_ptr = sec_r.read_64()
                u_ptr = sec_r.read_64()
                field = self.typeParse(types, t_ptr-section_base_addr, section_data, section_base_addr)
                field_name = self.resolve_name(section_data, nptr-section_base_addr, 0)
                nl = len(field_name)
                if nl != 0:
                    field.field_tag = self.resolve_tag( nptr, nl-section_base_addr, section_data )
                field.field_name = field_name
                field.field_anon = field_name == "" or u_ptr&1 != 0
                typ.fields.append(field)
        elif kinds[typ.kind] == "Func":
            i = r.read_16()
            o = r.read_16()
            o = o & ((1<<15) - 1)
            typ.is_variadic = o &(1<<15) != 0
            padding = r.read_32()
            if typ.flag & 1:
                self.parse_uncommon_type(typ, r, section_data, section_base_addr, types)
            for x in range(i):
                aa = r.read_64()
                if aa != 0:
                    a = self.typeParse(types, aa-section_base_addr, section_data, section_base_addr)
                    typ.func_args.append(a)
            # get return types
            for x in range(o):
                aa = r.read_64()
                if aa > section_base_addr:
                    a = self.typeParse( types, aa-section_base_addr, section_data, section_base_addr )
                    typ.func_ret_vals.append(a)
        elif kinds[typ.kind] == "Interface":
            pkg_off = r.read_64()
            if pkg_off != 0:
                n = self.resolve_name( section_data, pkg_off-section_base_addr, 0)
                typ.package_path = n
            ptr_methods = r.read_64()
            num_methods = r.read_64()
            cap = r.read_64()
            if typ.flag&1 != 0:
                self.parse_uncommon_type(typ, r, section_data, section_base_addr, types)
            sec_r = ByteReader(section_data)
            imeth_size = 8
            int_32_ptr = True
            for i in range(num_methods):
                meth = TypeMethods()
                sec_r.seek(ptr_methods+i*imeth_size-section_base_addr, sec_r.SEEK_START)
                name_off = sec_r.read_32()
                if name_off != 0:
                    n = self.resolve_name(section_data, name_off, 0)
                    meth.name = n
                type_off = sec_r.read_32()
                if type_off != 0:
                    meth.type = self.typeParse(types, type_off, section_data, section_base_addr)
                typ.methods.append(meth)
        elif kinds[typ.kind] == "Array":
            element_addr = r.read_64()
            if element_addr != 0:
                e = self.typeParse(types, element_addr-section_base_addr, section_data, section_base_addr)
                typ.element = e
            t = r.read_64()
            l = r.read_64()
            typ.length = l
            if typ.flag & 1:
                self.parse_uncommon_type(typ, r, section_data, section_base_addr, types)
        elif kinds[typ.kind] == "Map":
            key_addr = r.read_64()
            if key_addr != 0:
                k = self.typeParse(types, key_addr-section_base_addr, section_data, section_base_addr)
                typ.key = k
            element_addr = r.read_64()
            if element_addr != 0:
                e = self.typeParse(types, element_addr-section_base_addr, section_data, section_base_addr)
                typ.element = e
        elif kinds[typ.kind] == "Chan":
            element_addr = r.read_64()
            if element_addr != 0:
                e = self.typeParse(types, element_addr-section_base_addr, section_data, section_base_addr)
                typ.element = e
            typ.chan_dir = r.read_64()
            if typ.flag & 1:
                self.parse_uncommon_type(typ, r, section_data, section_base_addr, types)
        return typ

    def resolve_name( self, section_data, offset, flag ):
        nl = struct.unpack(">H", section_data[offset + 1:offset + 1+2])[0]

        str_data = struct.unpack( '{}s'.format(nl), section_data[offset+3:offset+3+nl])[0]
        str_data = str_data.decode("UTF-8")
        if flag & 2:
            str_data = str_data[1:]
        return str_data
    
    def fix_string(self, str_data):
        s = ""
        for x in str_data:
            if x < 0x20 or x > 0x7e:
                if s.endswith(' '):
                    continue
                s = s + " "
            else:
                s = s + chr(x)
        return s.strip()

    def resolve_tag( self, offset, name_len, section_data ):
        o = offset + 3 + name_len
        tl = struct.unpack(">H", section_data[o:o+2] )[0]
        if tl == 0:
            return ""
        str_data = struct.unpack( '{}s'.format(tl), section_data[o+2:o+2+tl])[0]
        str_data = self.fix_string(str_data)
        return str_data

    def parse_uncommon_type( self, typ, r, section_data, section_base_addr, types ):
        pkg = r.read_32( )
        if pkg != 0 and typ.package_path == "":
            n = self.resolve_name(section_data, pkg, 0)
            typ.package_path = n
        typ.methods = self.parse_methods( r, section_data, section_base_addr, types )
        print("")

    def parse_methods( self, r, section_data, section_base_addr, types ):
        mcount = r.read_16()
        xcount = r.read_16()
        moff = r.read_32()
        padding = r.read_32()
        if mcount == 0:
            return []
        r.seek(moff-16, r.SEEK_CURRENT)
        methods = []
        for i in range(mcount):
            name = r.read_32()
            mtype = r.read_32()
            ifn = r.read_32()
            tfn = r.read_32()
            if name == 0 or name > len(section_data):
                continue
            m = TypeMethods()
            nm = self.resolve_name( section_data, name, 0 )
            m.name = nm
            if mtype != 0:
                m.type = self.typeParse( types, mtype, section_data, section_base_addr )
            m.func_call_offset = tfn
            m.iface_call_offset = ifn
            methods.append(m)
        return methods
