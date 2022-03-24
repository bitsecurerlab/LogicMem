import mmap, struct, os, sys
from time import gmtime, strftime, time
import LinuxMemory as linux

class AddressSpace(linux.AMD64PagedMemory):
#class AddressSpace():
    def __init__(self, mem_path, dtb = 0, verbose = 0):
        try:
            f = os.open(mem_path, os.O_RDONLY)
        except:
            print("Error: open image failed!\n")
            sys.exit(1)
        # mapping memory snapshot to memory
        try:
            self.mem = mmap.mmap(f, 0, mmap.MAP_SHARED, mmap.ACCESS_READ)
        except:
            print("Error: mapping memory snapshot failed!\n")
        self.verbose = verbose
        self.mem_path = mem_path
        self.image_name = os.path.basename(self.mem_path)
        self.dtb_paddr = dtb
        self.version_index = 0
        if not os.path.exists(self.image_name + '_metadata'):
            self.mem.seek(0)
            if b'ELF' in self.mem.read(6):
                self.has_elf_header = True
                self.offset = self.parse_elf_header()
                print("elf header", self.offset)
            else:
                self.has_elf_header = False
                print("no elf header")

            #identify Linux kernel version
            self.LinuxVersion = self.findLinuxVersion()
            print("linux version", self.LinuxVersion)
            #recover kernel symbols
            if not os.path.exists(self.image_name + '_symbol_table'):
                version_num = self.LinuxVersion.split('.')
                if int(version_num[0]==4):
                    if int(version_num[1]) < 6:
                        self.find_kallsyms_address_pre_46()
                    else:
                        self.find_kallsyms_address(self.version_index)
                elif int(version_num[0]) < 4:
                    exit(0)
                    self.find_kallsyms_address_pre_46()
                else:
                    self.find_kallsyms_address(self.version_index)

            # find dtb vaddr from memory snapshot
            # This symbol address is shifted by virtual kaslr shift
            # the same symbol recovered from the kernel symbol table is not shifted
            # substracting one from another, we can get the virtual kaslr shift
            # it's possible that SYMBOL(swapper_pg_dir) cannot be found from the memory snapshot
            vdtb_idx = self.mem.find(b'SYMBOL(swapper_pg_dir)=') + len("SYMBOL(swapper_pg_dir)=")
            if vdtb_idx-len("SYMBOL(swapper_pg_dir)=")>0:
                self.dtb_vaddr = '0x' + self.mem_read(vdtb_idx, 16)
                print("dtb_vaddr", self.dtb_vaddr)
            else:
                print("cannot find dtb_vaddr")
                self.dtb_vaddr = None
            #self.find_kallsyms_address()
            self.kaslr_shift_vtop = self.kaslr_vtop_shift('kallsyms_on_each_symbol')
            self.kaslr_shift_vtov, self.dtb_paddr = self.kaslr_vtov_shift()
            print("vtop shift {0} vtov shift {1} dtb_paddr {2}".format(hex(self.kaslr_shift_vtop), hex(self.kaslr_shift_vtov), hex(self.dtb_paddr)))

    def find_page_table(self, dtb):
        offset = dtb & 0xfff
        for step in range(offset, self.mem.size(), 4096):
            if self.maybe_vtop(self.dtb_vaddr, step)==step:
                print("found dtb")
    def log(self, message):
        print('%s\t%s' %(strftime("%Y-%m-%d %H:%M:%S", gmtime()), message))
        sys.stdout.flush()
    # locate index of a certain string in the memory snapshot
    def mem_find(self, target_string):
        pass
    # read bytes from the memory snapshot and return a string
    def mem_read(self, index, length):
        self.mem.seek(index)
        return self.mem.read(length).decode('utf-8')
    def translate(self, addr):
        for input_addr, output_addr, length in self.offset:
            if addr >= input_addr and addr < input_addr + length:
                return output_addr + (addr - input_addr)
            if addr < input_addr:
                return None
        return None
    def read_memory(self, paddr, length):
        if self.has_elf_header:
            paddr = self.translate(paddr)
            if not paddr:
                return None
        if self.mem.size()-paddr < length:
            return None
        self.mem.seek(paddr)
        return self.mem.read(length)
    def findLinuxVersion(self):
        version_idx = self.mem.find(b'Linux version 5')
        if version_idx < 0:
            version_idx = self.mem.find(b'Linux version 4')
        if version_idx < 0:
            version_idx = self.mem.find(b'Linux version 3')
        if version_idx < 0:
            version_idx = self.mem.find(b'Linux version 2')
        if version_idx < 0:
            print('Error: cannot find Linux version or it is too old')
            return 0
        print("linux version index", hex(version_idx))
        self.version_index = version_idx
        self.mem.seek(version_idx + len('Linux version '))
        version = self.mem.read(8).decode('utf-8')
        major_ver_idx = version.index('.')
        minor_ver_idx = version[major_ver_idx+1:].index('.')
        return version[:major_ver_idx+minor_ver_idx+1]

    def _read_memory(self, paddr, length):
        '''
        This function is for reading elf header
        '''
        if paddr > 1024:
            sys.exit(1)
        self.mem.seek(paddr)
        value = self.mem.read(length)
        if not value:
            print("Error: fail to read memory at", hex(paddr))
        elif length == 2:
            value = struct.unpack('<H', value)[0]
        elif length == 4:
            value = struct.unpack('<I', value)[0]
        elif length == 8:
            value = struct.unpack('<Q', value)[0]
        return value

    def parse_elf_header(self):
        '''
        Parse elf header 64
        '''
        #elf64_header definition from Volatility
        elf64_header = {
            'e_ident' : [ 0, ['String', dict(length = 16)]],
            'e_type' : [ 16, ['Enumeration', dict(target = 'unsigned short', choices = {
                0: 'ET_NONE',
                1: 'ET_REL',
                2: 'ET_EXEC',
                3: 'ET_DYN',
                4: 'ET_CORE',
                0xff00: 'ET_LOPROC',
                0xffff: 'ET_HIPROC'})]],
            'e_machine' : [ 18, ['unsigned short']],
            'e_version' : [ 20, ['unsigned int']],
            'e_entry' : [ 24, ['unsigned long long']],
            'e_phoff' : [ 32, ['unsigned long long']],
            'e_shoff' : [ 40, ['unsigned long long']],
            'e_flags' : [ 48, ['unsigned int']],
            'e_ehsize'    : [ 52, ['unsigned short']],
            'e_phentsize' : [ 54, ['unsigned short']],
            'e_phnum'     : [ 56, ['unsigned short']],
            'e_shentsize' : [ 58, ['unsigned short']],
            'e_shnum'     : [ 60, ['unsigned short']],
            'e_shstrndx'  : [ 62, ['unsigned short']],
        }
        elf64_pheader = {
            'p_type' : [ 0, ['Enumeration', dict(target = 'unsigned int', choices = {
                0: 'PT_NULL',
                1: 'PT_LOAD',
                2: 'PT_DYNAMIC',
                3: 'PT_INTERP',
                4: 'PT_NOTE',
                5: 'PT_SHLIB',
                6: 'PT_PHDR',
                7: 'PT_TLS',
                0x60000000: 'PT_LOOS',
                0x6fffffff: 'PT_HIOS',
                0x70000000: 'PT_LOPROC',
                0x7fffffff: 'PT_HIPROC'})]],
            'p_flags' : [ 4, ['unsigned int']],
            'p_offset' : [ 8, ['unsigned long long']],
            'p_vaddr' : [ 16, ['unsigned long long']],
            'p_paddr' : [ 24, ['unsigned long long']],
            'p_filesz' : [ 32, ['unsigned long long']],
            'p_memsz' : [ 40, ['unsigned long long']],
            'p_align' : [ 48, ['unsigned long long']],
        }
        header_size = 56
        e_phoff = self._read_memory(elf64_header['e_phoff'][0], 4)
        e_phnum = self._read_memory(elf64_header['e_phnum'][0], 4)
        if e_phnum > 128:
            e_phnum = 128
        #e_phoff = 64
        #e_phnum = 7
        runs = []
        for i in range(e_phnum):
            idx = i * header_size
            p_type = self._read_memory(e_phoff + idx + elf64_pheader['p_type'][0], 2)
            p_filesz = self._read_memory(e_phoff + idx + elf64_pheader['p_filesz'][0], 8)
            p_memsz = self._read_memory(e_phoff + idx + elf64_pheader['p_memsz'][0], 8)
            if p_type != 1 or p_filesz == 0 or p_filesz != p_memsz:
                continue
            p_paddr = self._read_memory(e_phoff + idx + elf64_pheader['p_paddr'][0], 8)
            p_offset = self._read_memory(e_phoff + idx + elf64_pheader['p_offset'][0], 8)
            p_memsz = self._read_memory(e_phoff + idx + elf64_pheader['p_memsz'][0], 8)
            runs.append((int(p_paddr), int(p_offset), int(p_memsz)))
        return runs
    def find_kallsyms_address_pre_46(self):
        pass
    def find_token_table(self, kallsyms_names_paddr):
        # token_table address is larger than kallsyms_names_paddr
        # Start search from kallsyms_names_paddr
        self.log("Start to find kallsyms_token_table")
        #Estimisted gap 4096*0x100
        kallsyms_token_table_addr = kallsyms_names_paddr #+ 4096*250
        candidate = []
        # Read the content
        for step in range(kallsyms_token_table_addr, self.mem.size(), 8):
            kallsyms_token_table = ""
            kallsyms_token_table_v = []
            # Table_size is larger than 512 in reality
            table_size = 512/8
            init_addr = step
            while table_size:
                content = self.read_memory(init_addr, 8)
                if not content:
                    break
                #print(content)
                content = "".join(map(chr, content))
                #for item in content:
                #    kallsyms_token_table_v.append(struct.unpack("<c", item)[0])
                kallsyms_token_table += content
                init_addr += 8
                table_size -= 1
            if table_size > 1:
                continue
            table_size = 512/8

            #print "t in table", kallsyms_token_table.count('\x00'), kallsyms_token_table.count('r'), len(kallsyms_token_table)
            # table length is less than 1000. around 300 zeros in it. let's exam 512 element of them.
            '''
                The characters in token_table are valid as per naming rules; they are combinations of
                letters, numbers and symbols like underscores
            '''
            # I changed this range for ARM64 images, it used to be 46-125 for x86_64
            if not all(ord(c)>=36 and ord(c)<125 or ord(c)==0 for c in kallsyms_token_table):
                #print "pass"
                continue
            '''
                The elements in token_table in grouped and bounded by '\x00'
                no successive apperance of '\x00'
            '''
            if "\x00\x00" in kallsyms_token_table:
                #print "not pass"
                continue
            '''
                Compute the distance of each '\x00'. distance >= 1 and is normally less than 15.
                15 is somehow experimental.
            '''
            zero_index = [i for i, j in enumerate(kallsyms_token_table) if j == '\x00']
            for idx in reversed(range(1, len(zero_index))):
                zero_index[idx] = zero_index[idx] - zero_index[idx-1]
            #21 is somehow based on heuristic
            if any(c > 21 for c in zero_index):
                #print zero_index
                continue
            candidate.append(step)
            break
        if len(candidate) == 0:
            print("kallsyms_token_table not found")
        else:
            #print "found kallsyms_token_table_addr"
            self.log("kallsyms_token_table found")
            '''
            with open("table", 'w') as output:
                for item in kallsyms_token_table:
                    output.write(str((item, hex(int(ord(item)))))+'\n')
            '''
            return candidate[0]

    def find_token_index(self, token_table_paddr):
        self.log("Start to find kallsyms_token_index")
        result = 0
        for kallsyms_token_index_addr in range(token_table_paddr, self.mem.size(), 8):
            kallsyms_token_index = []
            kallsyms_token_index_v = []
            # From script/kallsyms.c, it has 256 entry, 256*2/8 = 64
            index_size = 64
            #print "index_addr", hex(kallsyms_token_index_addr), index_size
            init_addr = kallsyms_token_index_addr
            while index_size:
                content = self.read_memory(init_addr, 8)
                if not content:
                    break
                for idx in range(0, 7, 2):
                    kallsyms_token_index.append(content[idx:idx+2])
                init_addr += 8
                index_size -= 1
            if index_size > 1:
                continue
            index_size = 64
            for index in range(len(kallsyms_token_index)):
                content = struct.unpack("<H", kallsyms_token_index[index])
                kallsyms_token_index_v.append(content[0])
                #print content
                #print [i for i in kallsyms_token_index[index]]
            #print "len of token index array", len(kallsyms_token_index_v)
            '''
                The token index start from zero, and in an increasing order.
            '''
            if not kallsyms_token_index_v[0] == 0:
                continue
            if kallsyms_token_index_v[1] == 0:
                continue
            #print kallsyms_token_index_v
            print("kallsyms_token_index_addr", hex(kallsyms_token_index_addr))
            result = kallsyms_token_index_addr
            break
        self.log("kallsyms_token_index found")
        '''
        with open("index", 'w') as output:
            for item in kallsyms_token_index_v:
                output.write(hex(int(str(item)))+'\n')
        '''
        #for index in range(len(kallsyms_token_index)):
        #    print [c for c in kallsyms_token_index[index]]
        if not result:
            print("Cannot find token_index")
        else:
            return result
    def extract_kallsyms_symbols(self, symbol_name,
                                    kallsyms_names_addr,
                                    name_size,
                                    kallsyms_num_syms,
                                    kallsyms_token_table_addr,
                                    kallsyms_token_index_addr):
        size = kallsyms_num_syms
        # 4.11.bin
        #kallsyms_names_addr = 0xffffffff81b6bf88 + 0x1c400000
        # 4.12.bin
        #kallsyms_names_addr = 0xffffffff81b6bf88 + 0x5400000
        #kallsyms_names_addr = 0xffffffff81479600
        #kallsyms_names_addr = self.vtop(kallsyms_names_addr)
        if not kallsyms_names_addr:
            print("[-]Error: invalid kallsyms_names_addr")
            exit(0)
        kallsyms_names = bytearray()

        print("kallsyms_token_table_addr paddr", kallsyms_token_table_addr)
        if not kallsyms_token_table_addr:
            print("[-]Error: invalid kallsyms_token_table_addr")
            exit(0)
        kallsyms_token_table = ""
        kallsyms_token_table_v = []

        #kallsyms_token_index_addr = 0xffffffff814bded0
        # 4.11.bin
        #kallsyms_token_index_addr = 0xffffffff81c82090 + 0x1c400000
        # 4.12.bin
        #kallsyms_token_index_addr = 0xffffffff81c82090 + 0x5400000

        #kallsyms_token_index_addr = self.vtop(kallsyms_token_index_addr)
        if not kallsyms_token_index_addr:
            print("[-]Error: invalid kallsyms_token_index_addr")
            exit(0)
        kallsyms_token_index = []
        kallsyms_token_index_v = []
        #kallsyms_names_addr =  0x1a171ae0 + 16
        # Extract kallsyms_names
        while name_size:
            content = self.read_memory(kallsyms_names_addr, 4096)
            kallsyms_names.extend(content)
            kallsyms_names_addr += 4096
            name_size -= 1

        #print kallsyms_names
        '''
        with open("names", 'w') as output:
            for item in kallsyms_names:
                output.write(str((item, ord(item)))+'\n')
        '''


        # Extract kallsyms_token_table
        table_size = (kallsyms_token_index_addr - kallsyms_token_table_addr)/8
        table_size = 1200
        #kallsyms_token_table_addr = 0x1a28c098
        #table_size = 512
        #kallsyms_token_table_addr -= 16
        while table_size+32:
            content = self.read_memory(kallsyms_token_table_addr, 8)
            #for item in content:
            #    kallsyms_token_table_v.append(struct.unpack("<c", item)[0])
            kallsyms_token_table += content.decode('utf-8', errors='ignore')
            kallsyms_token_table_addr += 8
            table_size -= 1

        print("length of token table", hex(len(kallsyms_token_table)))
        tmp = ''
        '''
        with open("table", 'w') as output:
            for item in kallsyms_token_table:
                output.write(str((item, ord(item)))+'  ')
        '''
        #print [ord(i) for i in kallsyms_token_table]

        # Extract kallsyms_token_index
        # Not sure about the index_size
        # From script/kallsyms.c, it has 256 entry, 256*2/8 = 64
        index_size = 64
        #print "index_addr", hex(kallsyms_token_index_addr), index_size
        #kallsyms_token_index_addr = 0x1a28c430
        while index_size:
            content = self.read_memory(kallsyms_token_index_addr, 8)
            for idx in range(0, 7, 2):
                kallsyms_token_index.append(content[idx:idx+2])
            kallsyms_token_index_addr += 8
            index_size -= 1
        for index in range(len(kallsyms_token_index)):
            content = struct.unpack("<H", kallsyms_token_index[index])
            kallsyms_token_index_v.append(content[0])
            #print content
            #print [i for i in kallsyms_token_index[index]]
        #print "len of token index array", len(kallsyms_token_index_v)
        '''
        with open("index", 'w') as output:
            for item in kallsyms_token_index_v:
                output.write(str(item)+'  ')
        print "expand compressed strings"
        '''
        off = 0
        for index in range(size+1):
            if off == -1:
                break
            off = self.kallsyms_expand_symbol(off, symbol_name, kallsyms_names, kallsyms_token_table, kallsyms_token_index_v)
        #off = self.kallsyms_expand_symbol(off, kallsyms_names, kallsyms_token_table_v, kallsyms_token_index_v)
    def kallsyms_expand_symbol(self, off, symbol_name,
                                kallsyms_names,
                                kallsyms_token_table, kallsyms_token_index):
        skipped_first = 0
        max_len = 128
        '''
            Get the index of compressed symbol length from the first symbol byte.
        '''
        data = off
        # Convert char to decimal.
        #length = ord(kallsyms_names[data])
        length = kallsyms_names[data]
        data += 1
        '''
            length should be an int
            Update the offset to return the offset for the next symbol on
	        the compressed stream.
        '''
        #print "length", length
        off += length + 1
        result = ''
        '''
            For every byte on the compressed symbol data, copy the table
	        entry for that byte.
        '''

        while length:
            #print "token_index", len(kallsyms_names), data, length, ord(kallsyms_names[data])
            if data >= len(kallsyms_names)-1:
                print("names out of bound")
                return -1
            #if ord(kallsyms_names[data]) >= len(kallsyms_token_index):
            if kallsyms_names[data] >= len(kallsyms_token_index):
                print("token index out of bound")
                return -1
            #token_table_index = kallsyms_token_index[ord(kallsyms_names[data])]
            token_table_index = kallsyms_token_index[kallsyms_names[data]]
            #print "token_table_index", token_table_index
            #print "len", length
            data += 1
            length -= 1

            while ord(kallsyms_token_table[token_table_index]):
                #print "index", token_table_index, ord(kallsyms_token_table[token_table_index])
                if skipped_first:
                    if max_len <= 1:
                        break
                    result += kallsyms_token_table[token_table_index]
                    max_len -= 1
                else:
                    skipped_first = 1
                token_table_index += 1

        #print "result:", result
        symbol_name.append(result)
        return off
    def find_kallsyms_address(self, init_addr = 0):
        kallsyms_address = 0
        found = 0
        for step in range(init_addr, self.mem.size(), 4096):
            page = self.read_memory(step, 4096)
            if not page:
                continue
            value = list(struct.unpack("<1024I", page))
            # heuristic: if more than half values are 0, this is not a candidate kallsyms_addresses[]
            if value.count(0) > len(value):
                continue
            # kallsyms_addresses[] contains a sequence of increasing offsets
            # if the length of this sequence is larger than a threshold, we consider it as a candidate
            index = 0
            while index < len(value):
                tmp_index = index + 1
                current_value = value[index]
                while tmp_index < len(value) and value[tmp_index] > current_value:
                    current_value = value[tmp_index]
                    tmp_index += 1
                if tmp_index - index > 100:
                    found = 1
                    break
                index = tmp_index
            if not found:
                continue
            # it also contains a sequence of unsigned int negative numbers in descending order
            index = 0
            while index < len(value):
                tmp_index = index + 1
                current_val = value[index]
                while tmp_index < len(value) and value[tmp_index] < current_val:
                    current_val = value[tmp_index]
                    tmp_index += 1
                if value[index] < 0xf0000000:
                    break
                if tmp_index - index > 300:
                    if index % 2 == 1:
                        index += 1
                    kallsyms_address = step + index*4
                    break
                index = tmp_index
            if kallsyms_address:
                break
        if not kallsyms_address:
            print("ERROR: Cannot find kallsyms_addresses[]")
            sys.exit(1)
        print("kallsyms addr", hex(kallsyms_address))
        # Continue to search for kallsyms_relative_base
        kallsyms_relative_base = kallsyms_address
        content = self.read_memory(kallsyms_relative_base, 0x8)
        value = struct.unpack('<Q', content)
        while value[0] & 0xffffffff00000000 != 0xffffffff00000000:
            kallsyms_relative_base += 0x8
            content = self.read_memory(kallsyms_relative_base, 0x8)
            value = struct.unpack('<Q', content)
        # This should be the kallsyms_relative_base address
        kallsyms_relative_base_v = value[0]
        # The value next to it should be kallsyms_num_syms
        content = self.read_memory(kallsyms_relative_base+0x8, 0x8)
        kallsyms_num_syms = struct.unpack('<Q', content)[0]
        # if kallsyms_num_syms is invalid, search again
        if kallsyms_num_syms > 1200000 or kallsyms_num_syms == 0:
            self.find_kallsyms_address(kallsyms_relative_base)
            return
        # Then the initial address of kallsyms_offsets can be found by
        # kallsyms_relative_base - kallsyms_num_syms/2*8
        if not kallsyms_num_syms%2==0:
            kallsyms_num_syms += 1
        kallsyms_offsets = int(kallsyms_relative_base - (kallsyms_num_syms/2 * 8))
        print("kallsyms_offset addr", kallsyms_offsets)
        # Now we have kallsyms_offsets and kallsyms_relative_base, we can
        # recover the symbol addresses.
        symbol_address = []
        offsets = []
        number_sysms = kallsyms_num_syms
        while number_sysms >= -1:
            content = self.read_memory(kallsyms_offsets, 0x8)
            #print content
            value = struct.unpack('<2I', content)
            #print value
            for item in value:
                #print "physical addr: ", hex(kallsyms_offsets), "content", [hex(int(ord(c))) for c in content], "value", hex(item)
                if item > 0xf000000:
                    symbol_address.append(kallsyms_relative_base_v + (item^0xffffffff)-0x5400000)
                    offsets.append(item)
                else:
                    symbol_address.append(item)
                    offsets.append(item)
                    #symbol_address.append(kallsyms_relative_base_v + item)
            kallsyms_offsets += 0x8
            number_sysms -= 2
        kallsyms_names_addr = kallsyms_relative_base + 16
        kallsyms_token_table_addr = self.find_token_table(kallsyms_names_addr)
        kallsyms_token_index_addr = self.find_token_index(kallsyms_token_table_addr)
        symbol_name = []
        # Size of kallsyms_names in page granularity.
        # It's ok to use a larger name size, if we do not know the exact size.
        name_size = 0x115*2
        self.extract_kallsyms_symbols(symbol_name, kallsyms_names_addr, name_size, kallsyms_num_syms, kallsyms_token_table_addr, kallsyms_token_index_addr)
        #print symbol_name
        with open(self.image_name + "_symbol_table", 'w') as output:
            for index in range(min(len(symbol_address), len(symbol_name))):
                output.write(hex(symbol_address[index]) + "\t" + hex(offsets[index]) + " " + symbol_name[index] + "\n")

    def kaslr_vtop_shift(self, target):
        target_vaddr = 0
        with open(self.image_name+'_symbol_table', 'r') as symbol:
            content = symbol.read().split('\n')
            for item in content[:-1]:
                tmp = item.split()
                if '_kstrtab_' + target in tmp[-1]:
                    # removing the ending 'L' of a hex string
                    tmp[0] = tmp[0].rstrip('L')
                    target_vaddr = int(tmp[0], 16)
                    break
        if target_vaddr == 0:
            # cannot find __kstrtab_`target` in symbol table
            # find physical address of dtb and compute kaslr shift
            # by dtb_vaddr - dtb_paddr
            # but this is problemtic because dtb_vaddr is virtual address after shift
            # skip for now
            print("Cannot find _kstrtab_{0} from kernel symbol, currently not supported".format(target))
            sys.exit(1)
            self.dtb_paddr = self.find_dtb()
            return int(self.dtb_paddr, 16) - self.dtb_paddr
        pg_offset = target_vaddr & 0xfff
        # utilize the fact that vaddr and paddr has the same page offset
        # scan every page at the same pg_offset until we find the same string
        for step in range(pg_offset, self.mem.size(), 4096):
            v = self.read_memory(step, len(target))
            if not v:
                continue
            if target == v.decode('utf-8', errors='ignore'):
                print("kaslr_shift_vtop", hex(target_vaddr-step))
                return target_vaddr - step
        return 0
    def kaslr_vtov_shift(self):
        if not os.path.exists(self.image_name + '_symbol_table'):
            print("cannot find symbol table file, exit")
            sys.exit(1)
        with open(self.image_name + "_symbol_table", 'r') as symbol:
            content = symbol.read().split('\n')
            symbol_name = ["swapper_pg_dir", "init_level4_pgt", "init_top_pgt"]
            for item in content[:-2]:
                tmp = item.split()
                if any(c in tmp[-1] for c in symbol_name):
                    tmp[0] = tmp[0].rstrip('L')
                    dtb_symbol_vaddr = int(tmp[0], 16)
                    if self.dtb_vaddr:
                        if self.dtb_paddr == 0:
                            #if dtb_paddr is unknown, calculate it here (dtb_symbol_vaddr - kaslr_vtop_shift)
                            return int(self.dtb_vaddr, 16) - dtb_symbol_vaddr, dtb_symbol_vaddr - self.kaslr_shift_vtop
                        else:
                            print("dtb_vaddr: {0} dtb_symbol_vaddr: {1}".format(hex(int(self.dtb_vaddr, 16)), hex(dtb_symbol_vaddr)))
                            return int(self.dtb_vaddr, 16) - dtb_symbol_vaddr, self.dtb_paddr
                    else:
                        print("Cannot find dtb_vaddr, exit")
                        sys.exit(1)
        print("Cannot find vtov shift, exit")
        sys.exit(1)
    def find_string_paddr(self, target_string):
        for step in range(0, self.mem.size(), 4096):
            page = self.read_memory(step, 4096)
            if not page:
                continue
            for index in range(0, 4096, 8):
                if target_string in page[index:index+len(target_string)].decode('utf-8', errors='ignore'):
                    print("Found {0} at {1}".format(target_string, hex(step+index)))
                    return step+index
        print("Cannot found {0}".format(target_string))
    def find_task_struct(self, addr):
        '''
        This function is used to find the address of first task_struct (i.e., init_task)
        the argument `addr` is the paddr of `swapper\0` string found by searching the string in memory dump.
        '''
        page = self.read_memory(addr, 4096)
        value = struct.unpack('<512Q', page)
        for index in range(len(value)):
            vaddr = value[index]
            if value == 0:
                continue
            paddr = self.vtop(vaddr)
            if paddr:
                for gap in range(addr, addr+3000, 8):
                    target_comm_paddr = paddr + addr+3000-gap
                    target_comm = self.read_memory(target_comm_paddr, 8)
                    if not target_comm:
                        continue
                    if 'swapper' in target_comm.decode('utf-8', errors='ignore'):
                        if addr+3000-gap < 500:
                            continue
                        print("found init_task at", hex(paddr))
                        return
    def find_next_task(self, init_paddr):
        '''
        find the next task from the first init_task, reason about the next task_struct instead of the first
        `swapper` process.
        '''
        comm_offset = 0
        facts = self.extract_facts(init_paddr, 4096, 0)
        for item in facts['strings']:
            if 'swapper' in item[1]:
                comm_offset = item[0]
        if comm_offset == 0:
            print('swapper not found')
            return -1
        for index in range(len(facts['pointers'])):
            task_next = facts['pointers'][index]
            if task_next[1] == init_paddr + task_next[0]:
                continue
            next_ts_base_addr = task_next[1] - task_next[0]
            comm = self.extract_facts(next_ts_base_addr + comm_offset, 8, 0)
            if not comm:
                continue
            if len(comm['strings'])==0:
                continue
            else:
                #print(comm['strings'], task_next[0])
                task_prev = facts['pointers'][index+1]
                if task_prev[1] == 0:
                    continue
                prev_ts_base_addr = task_prev[1] - task_next[0]
                task_prev_comm = self.extract_facts(prev_ts_base_addr + comm_offset, 8, 0)
                if not task_prev_comm or len(task_prev_comm['strings'])==0:
                    continue
                else:
                    return next_ts_base_addr
        return 0

    def find_next_module(self, init_paddr):
        facts = self.extract_facts(init_paddr, 8, 0)
        if not facts or len(facts['pointers'])==0:
            print("modules address invalid")
            return -1
        module = facts['pointers'][0]
        module_fact = self.extract_facts(module[1], 24, 0)
        if module_fact and module_fact['strings']:
            new_facts = self.extract_facts(module[1], 8, 0)
            if not new_facts or len(new_facts['pointers']) == 0:
                return -1
            module = new_facts['pointers'][0]
            module_fact = self.extract_facts(module[1], 24, 0)
            if module_fact and module_fact['strings']:
                return module[1] - 8
        print("module structure base addr not found")
        return 0

    def v(self, size, content):
        s = '<' + str(size/8) + 'Q'
        return struct.unpack(s, content)

    def find_modules(self):
        '''
        This function is to locate the golbal symbol 'modules'. It first starts from a random kernel module
        that is very likely to be loaded and identifies its location in the memory as well as the next and prev pointers in that module structure.
        Then it traverse the module list until reaching the first one in the double linked list.
        We rely on the following evidence to find the top one in the list:
                                         | module_struct |     | module_struct |
            global symbol `modules` -->  | next          | --> | next          |
                                         | prev          |     | prev          |
                                         | module name   |     | module name   |
            The prev of the first element points to the global symbol module, and it does not have a string value (module name) below.
            In other words, it prev points to a location where there is a string value below, then it is not the first element.
        Based on the above information, we can locate the global symbol `modules` in the memory.
        Then we just find its virtual address and put it in the profile.

        '''
        for step in range(0, self.mem.size(), 4096):
            page = self.read_memory(step, 4096)
            if not page:
                continue
            prev_ = 0
            next_ = 0
            last_next = 1
            last_prev = 0
            target_v = 1
            module_v = 0
            found = 0
            # We start from a random kernel module that is very likely to be loaded.
            module_name = "binfmt"
            #value = self.v(4096, page)
            value = struct.unpack('<512Q', page)
            for item in range(len(value)):
                str_content = page[item*8:(item+1)*8]
                if not str_content:
                    continue
                number = value[item]
                if "ipv6head" in str_content.decode('utf-8', errors='ignore'):
                #if self.isstring(str_content):
                    prev_ = value[item-1]
                    next_ = value[item-2]

                    if prev_ == next_:
                        continue
                    if not self.vtop(prev_) or not self.vtop(next_):
                        continue
                    #print "found ", str_content, hex(prev_), hex(next_), hex(step + item*8)

                    last_next = self.read_memory(self.vtop(prev_), 0x8)
                    if not last_next or not len(last_next) == 8:
                        continue
                    last_next_v = self.v(8, last_next)[0]
                    target = self.read_memory(self.vtop(last_next_v), 8)
                    if not target or not len(target) == 8:
                        continue
                    target_v = self.v(8, target)[0]
                    #print "prev_", hex(prev_), self.vtop(prev_), "next", hex(next_), self.vtop(next_), "module", hex(module_v), "target", hex(target_v), str_content, hex(step+item*8)
                    module_name = str_content
                    if target_v == next_:
                        found = 1
                    else:
                        found = 0
                    break
            if found:
                while self.isstring(module_name):
                    print("found new module", module_name)
                    next_ = self.read_memory(self.vtop(prev_), 8)
                    if not next_:
                        break
                    next_ = self.v(8, next_)[0]
                    module_name = self.read_memory(self.vtop(prev_)+16, 8)
                    prev_ = self.read_memory(self.vtop(prev_)+8, 8)
                    if not prev_:
                        break
                    prev_ = self.v(8, prev_)[0]

                    last_next = self.read_memory(self.vtop(prev_), 0x8)
                    if not last_next or not len(last_next) == 8:
                        continue
                    last_next_v = self.v(8, last_next)[0]
                    target = self.read_memory(self.vtop(last_next_v), 8)
                    if not target or not len(target) == 8:
                        continue
                    target_v = self.v(8, target)[0]


                if target_v == next_ and target_v > 0xffffffff00000000:
                    print("found modlues", hex(target_v), hex(module_v), hex(prev_))
                    #break
                    modules = 0
                    for step in range(0, self.mem.size(), 4096):
                        page = self.read_memory(step & 0xffffffffff000, 0x200 * 8)
                        if not page:
                            continue
                        value = self.v(4096, page)
                        for item in range(len(value)):
                            number = value[item]
                            if number == target_v:
                                if self.isstring(page[(item+1)*8:(item+2)*8]):
                                    continue
                                print("found global symbol at", hex(step + item*8), hex(number), hex(target_v))
                                modules = step + item*8

                    for step in range(0x0, 0xf0000000, 4096):
                        vaddr = step + 0xffffffff00000000
                        paddr = self.vtop(vaddr)
                        if paddr == modules & 0xffffffffff000:
                            print("found vaddr", hex(vaddr), hex(vaddr + (modules & 0xfff)))
                            self.log("Finish searching")

                        pass

        if not found:
            return
        print("the first module is at", hex(target_v))
        if target_v == 1:
            return

        # To find the golbal symbol modules, we need to search in the memory to find the location which contains target_v
        modules = 0
        for step in range(0, self.mem.size(), 4096):
            page = self.read_memory(step & 0xffffffffff000, 0x200 * 8)
            if not page:
                continue
            value = self.v(4096, page)
            for item in range(len(value)):
                number = value[item]
                if number == target_v:
                    if self.isstring(page[(item+1)*8:(item+2)*8]):
                        continue
                    print("found global symbol at", hex(step + item*8), hex(number), hex(target_v))
                    modules = step + item*8

        print (self.vtop(0xffffffff9e288ef0) == modules)

        for step in range(0x0, 0xf0000000, 4096):
            vaddr = step + 0xffffffff00000000
            paddr = self.vtop(vaddr)
            if paddr == modules & 0xffffffffff000:
                print("found vaddr", hex(vaddr), hex(vaddr + (modules & 0xfff)))
                self.log("Finish searching")

    def extract_facts(self, paddr, size = 4096, verbose = 0):
        '''
        TODO: handle strings larger than 8 bytes
        '''
        valid_pointer = []
        valid_long = []
        valid_int = []
        valid_string = []
        unknown_pointer = []
        content = self.read_memory(paddr, size)
        if not content:
            #print("No avaliable page")
            return {}
        value = struct.unpack('<%dQ' % (size/8), content)
        for index in range(len(value)):
            number = value[index]
            phys_addr = self.vtop(number)
            if phys_addr:
                valid_pointer.append([index*8, phys_addr])
                if verbose:
                    print("[-] ", index*8, hex(paddr+index*8), "pointer", hex(number), hex(self.vtop(number)), [c for c in content[index*8:index*8+8]])
            else:
                if number < 0xffff:
                    if number == 0x0:
                        valid_pointer.append([index*8, number])
                        if verbose:
                            print("[-] ", index*8, hex(paddr+index*8), "pointer", number, [c for c in content[index*8:index*8+8]])
                    else:
                        str_content = content[index*8:(index+1)*8].decode('utf-8', errors='ignore')
                        #if all(ord(c)>=36 and ord(c)<=122 or ord(c)==0 for c in str_content):
                        if all(c>=36 and c<=122 or c==0 for c in content[index*8:index*8+8]):
                            if len(str_content.replace('\x00', '')) >= 1:
                                valid_string.append([index*8, str_content.replace('\x00', '')])
                                if verbose:
                                    print("[-] ", index*8, hex(paddr+index*8), "string1: ", str_content, hex(number), [c for c in content[index*8:index*8+8]])
                        else:
                            valid_long.append([index*8, number])
                            if verbose:
                                print("[-] ", index*8, hex(paddr+index*8), "long", hex(number), [c for c in content[index*8:index*8+8]])
                elif number < 0xffffffffffff:
                    str_content = content[index*8:(index+1)*8].decode('utf-8', errors='ignore')
                    #if all(ord(c)>=36 and ord(c)<=122 or ord(c)==0 for c in str_content):
                    if all(c>=36 and c<=122 or c==0 for c in content[index*8:index*8+8]):
                        if len(str_content.replace('\x00', '')) >= 1:
                            valid_string.append([index*8, str_content.replace('\x00', '')])
                            if verbose:
                                print("[-] ", index*8, hex(paddr+index*8), "string2: ", str_content, hex(number), [c for c in content[index*8:index*8+8]])
                    else:
                        valid_long.append([index*8, number])
                        if verbose:
                            print("[-] ", index*8, hex(paddr+index*8), "long", hex(number), [c for c in content[index*8:index*8+8]])
                elif number == 0xffffffffffffffff:
                    pass
                else:
                    str_content = content[index*8:(index+1)*8].decode('utf-8', errors='ignore')
                    count = 0
                    for c in content[index*8:(index+1)*8]:
                        if c>=32 and c<=122:
                            count += 1
                    if count >= 4:
                        valid_string.append([index*8, str_content.replace('\x00', '')])
                        if verbose:
                            print("[-] ", index*8, hex(paddr+index*8), "string3: ", str_content, hex(number), [c for c in content[index*8:index*8+8]])
                    else:
                        unknown_pointer.append([index*8, number])
                        if verbose:
                            print("[-] ", index*8, hex(paddr+index*8), "unknow pointer: ", hex(number), [c for c in content[index*8:index*8+8]], str_content)
        # find integers
        value = struct.unpack('<%dI' % (size/4), content)
        for index in range(len(value)):
            number = value[index]
            if number < 0x17fff:
                valid_int.append([index*4, number])
                if verbose:
                    print("[-]", index*4, hex(number))
        facts = {}
        facts['pointers'] = valid_pointer
        facts['longs'] = valid_long
        facts['integers'] = valid_int
        facts['strings'] = valid_string
        return facts

def main():
    mem_path = sys.argv[1]
    addr_space = AddressSpace(mem_path, 0x50a0a000)
    print("dtb paddr", hex(addr_space.dtb_paddr), addr_space.dtb_vaddr)
    #addr_space.find_string_paddr('kthreadd')
    print(addr_space.vtop(0xffffffffa7013740+addr_space.kaslr_shift_vtov))
    #addr_space.find_task_struct(addr_space.find_string_paddr('kthreadd')-3000)
    #addr_space.find_modules()
    addr_space.extract_facts(1352742720, 4096, 1)


if __name__ == "__main__":
    main()
