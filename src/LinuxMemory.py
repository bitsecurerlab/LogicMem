import struct
ptrs_page = 2048
entry_size = 8
pde_shift = 21
ptrs_per_pde = 512
page_shift = 12
ptrs_per_pae_pgd = 512
ptrs_per_pae_pte = 512
class AMD64PagedMemory():
    """ Standard AMD 64-bit address space.
    This class implements the AMD64/IA-32E paging address space. It is responsible
    for translating each virtual (linear) address to a physical address.
    This is accomplished using hierachical paging structures.
    Every paging structure is 4096 bytes and is composed of entries.
    Each entry is 64 bits.  The first paging structure is located at the
    physical address found in CR3 (dtb).
    Additional Resources:
     - Intel(R) 64 and IA-32 Architectures Software Developer's Manual
       Volume 3A: System Programming Guide. Section 4.3
       http://www.intel.com/products/processor/manuals/index.htm
     - AMD64 Architecture Programmer's Manual Volume 2: System Programming
       http://support.amd.com/us/Processor_TechDocs/24593_APM_v2.pdf
     - N. Petroni, A. Walters, T. Fraser, and W. Arbaugh, "FATKit: A Framework
       for the Extraction and Analysis of Digital Forensic Data from Volatile
       System Memory" ,Digital Investigation Journal 3(4):197-210, December 2006.
       (submitted February 2006)
     - N. P. Maclean, "Acquisition and Analysis of Windows Memory,"
       University of Strathclyde, Glasgow, April 2006.
     - Russinovich, M., & Solomon, D., & Ionescu, A.
       "Windows Internals, 5th Edition", Microsoft Press, 2009.
    """
    order = 60
    pae = False
    checkname = 'AMD64ValidAS'
    paging_address_space = True
    minimum_size = 0x1000
    alignment_gcd = 0x1000
    #_longlong_struct = struct.Struct("<Q")
    skip_duplicate_entries = False
    dtb = 0

    def entry_present(self, entry):
        return entry and (entry & 1)

    def page_size_flag(self, entry):
        if (entry & (1 << 7)) == (1 << 7):
            return True
        return False

    def is_user_page(self, entry):
        return entry & (1 << 2) == (1 << 2)

    def is_supervisor_page(self, entry):
        return not self.is_user_page(entry)

    def is_writeable(self, entry):
        return entry & (1 << 1) == (1 << 1)

    def is_dirty(self, entry):
        return entry & (1 << 6) == (1 << 6)

    def is_nx(self, entry):
        return entry & (1 << 63) == (1 << 63)

    def is_accessed(self, entry):
        return entry & (1 << 5) == (1 << 5)

    def is_copyonwrite(self, entry):
        return entry & (1 << 9) == (1 << 9)

    def is_prototype(self, entry):
        return entry & (1 << 10) == (1 << 10)

    def get_2MB_paddr(self, vaddr, pgd_entry):
        paddr = (pgd_entry & 0xFFFFFFFE00000) | (vaddr & 0x00000001fffff)
        return paddr


    def pml4e_index(self, vaddr):
        '''
        This method returns the Page Map Level 4 Entry Index
        number from the given  virtual address. The index number is
        in bits 47:39.
        '''
        return (vaddr & 0xff8000000000) >> 39

    def get_pml4e(self, vaddr):
        '''
        This method returns the Page Map Level 4 (PML4) entry for the
        virtual address. Bits 47:39 are used to the select the
        appropriate 8 byte entry in the Page Map Level 4 Table.
        "Bits 51:12 are from CR3" [Intel]
        "Bits 11:3 are bits 47:39 of the linear address" [Intel]
        "Bits 2:0 are 0" [Intel]
        '''
        pml4e_paddr = (self.dtb_paddr & 0xffffffffff000) | ((vaddr & 0xff8000000000) >> 36)
        #print "get_pml4e", hex(pml4e_paddr)
        return self.read_long_long_phys(pml4e_paddr)

    def maybe_get_pml4e(self, vaddr, possible_dtb):
        '''
        This method returns the Page Map Level 4 (PML4) entry for the
        virtual address. Bits 47:39 are used to the select the
        appropriate 8 byte entry in the Page Map Level 4 Table.
        "Bits 51:12 are from CR3" [Intel]
        "Bits 11:3 are bits 47:39 of the linear address" [Intel]
        "Bits 2:0 are 0" [Intel]
        '''

        pml4e_paddr = (possible_dtb & 0xffffffffff000) | ((vaddr & 0xff8000000000) >> 36)
        #print "get_pml4e", hex(pml4e_paddr)
        return self.read_long_long_phys(pml4e_paddr)

    def get_pdpi(self, vaddr, pml4e):
        '''
        This method returns the Page Directory Pointer entry for the
        virtual address. Bits 32:30 are used to select the appropriate
        8 byte entry in the Page Directory Pointer table.
        "Bits 51:12 are from the PML4E" [Intel]
        "Bits 11:3 are bits 38:30 of the linear address" [Intel]
        "Bits 2:0 are all 0" [Intel]
        '''
        pdpte_paddr = (pml4e & 0xffffffffff000) | ((vaddr & 0x7FC0000000) >> 27)
        return self.read_long_long_phys(pdpte_paddr)

    def get_1GB_paddr(self, vaddr, pdpte):
        '''
        If the Page Directory Pointer Table entry represents a 1-GByte
        page, this method extracts the physical address of the page.
        "Bits 51:30 are from the PDPTE" [Intel]
        "Bits 29:0 are from the original linear address" [Intel]
        '''
        return (pdpte & 0xfffffc0000000) | (vaddr & 0x3fffffff)

    def pde_index(self, vaddr):
        return (vaddr >> pde_shift) & (ptrs_per_pde - 1)

    def pdba_base(self, pdpe):
        return pdpe & 0xFFFFFFFFFF000

    def get_pgd(self, vaddr, pdpe):
        pgd_entry = self.pdba_base(pdpe) + self.pde_index(vaddr) * entry_size
        return self.read_long_long_phys(pgd_entry)

    def pte_index(self, vaddr):
        return (vaddr >> page_shift) & (ptrs_per_pde - 1)

    def ptba_base(self, pde):
        return pde & 0xFFFFFFFFFF000

    def get_pte(self, vaddr, pgd):
        pgd_val = self.ptba_base(pgd) + self.pte_index(vaddr) * entry_size
        return self.read_long_long_phys(pgd_val)

    def pte_pfn(self, pte):
        return pte & 0xFFFFFFFFFF000

    def get_paddr(self, vaddr, pte):
        return self.pte_pfn(pte) | (vaddr & ((1 << page_shift) - 1))

    def vtop(self, vaddr):
        '''
        This method translates an address in the virtual
        address space to its associated physical address.
        Invalid entries should be handled with operating
        system abstractions.
        '''
        vaddr = int(vaddr)
        retVal = None
        pml4e = self.get_pml4e(vaddr)
        if not self.entry_present(pml4e):
            return None

        pdpe = self.get_pdpi(vaddr, pml4e)
        if not self.entry_present(pdpe):
            return retVal

        if self.page_size_flag(pdpe):
            return self.get_1GB_paddr(vaddr, pdpe)

        pgd = self.get_pgd(vaddr, pdpe)
        if self.entry_present(pgd):
            if self.page_size_flag(pgd):
                retVal = self.get_2MB_paddr(vaddr, pgd)
            else:
                pte = self.get_pte(vaddr, pgd)
                if self.entry_present(pte):
                    retVal = self.get_paddr(vaddr, pte)
        return retVal

    def maybe_vtop(self, vaddr, possible_dtb):
        '''
        This method translates an address in the virtual
        address space to its associated physical address.
        Invalid entries should be handled with operating
        system abstractions.
        '''
        vaddr = int(vaddr, 16)
        retVal = None
        pml4e = self.maybe_get_pml4e(vaddr, possible_dtb)
        if not self.entry_present(pml4e):
            return None

        pdpe = self.get_pdpi(vaddr, pml4e)
        if not self.entry_present(pdpe):
            return retVal

        if self.page_size_flag(pdpe):
            return self.get_1GB_paddr(vaddr, pdpe)

        pgd = self.get_pgd(vaddr, pdpe)
        if self.entry_present(pgd):
            if self.page_size_flag(pgd):
                retVal = self.get_2MB_paddr(vaddr, pgd)
            else:
                pte = self.get_pte(vaddr, pgd)
                if self.entry_present(pte):
                    retVal = self.get_paddr(vaddr, pte)
        return retVal

    def is_user_pointer(self, buf, idx):
        dest = (ord(buf[idx+7]) << 56) + (ord(buf[idx+6]) << 48) + (ord(buf[idx+5]) << 40) + (ord(buf[idx+4]) << 32) + (ord(buf[idx+3]) << 24) + (ord(buf[idx+2]) << 16) + (ord(buf[idx+1]) << 8) + ord(buf[idx])
        return dest


    def read_long_long_phys(self, addr):
        '''
        This method returns a 64-bit little endian
        unsigned integer from the specified address in the
        physical address space. If the address cannot be accessed,
        then the method returns None.
        This code was derived directly from legacyintel.py
        '''
        try:
            string = self.read_memory(addr, 8)
        except IOError:
            string = None
        if not string:
            #return obj.NoneObject("Unable to read_long_long_phys at " + hex(addr))
            return None
        longlongval, = struct.unpack("<Q", string)
        return longlongval

    def get_page_info(self, addr, length):
        info = {}
        idx = 0
        while idx < length:
            try:
                string = self.read_memory(addr, 8)
            except IOError:
                string = None
            if not string:
                return obj.NoneObject("Unable to read_long_long_phys at " + hex(addr))
            longlongval, = struct.unpack("<Q", string)
            info[addr] = string
            addr += 8
            idx += 8
        return info

    def get_available_pages(self, with_pte = False):
        '''
        This method generates a list of pages that are
        available within the address space. The entries in
        are composed of the virtual address of the page
        and the size of the particular page (address, size).
        It walks the 0x1000/0x8 (0x200) entries in each Page Map,
        Page Directory, and Page Table to determine which pages
        are accessible.
        '''
        # read the full pml4
        pml4 = self.read_memory(self.dtb_paddr & 0xffffffffff000, 0x200 * 8)
        if pml4 is None:
            return

        # unpack all entries
        pml4_entries = struct.unpack('<512Q', pml4)
        for key in pml4_entries:
            if key == 0:
                continue
            #print bin(key), hex(key)
        for pml4e in range(0, 0x200):
            vaddr = pml4e << 39
            pml4e_value = pml4_entries[pml4e]
            if not self.entry_present(pml4e_value):
                continue
            #print bin(pml4e_value), "pml4e_value", hex(pml4e_value)
            pdpt_base = (pml4e_value & 0xffffffffff000)
            pdpt = self.read_memory(pdpt_base, 0x200 * 8)
            if pdpt is None:
                continue

            pdpt_entries = struct.unpack('<512Q', pdpt)
            for pdpte in range(0, 0x200):
                vaddr = (pml4e << 39) | (pdpte << 30)
                pdpte_value = pdpt_entries[pdpte]
                if not self.entry_present(pdpte_value):
                    continue

                if self.page_size_flag(pdpte_value):
                    if with_pte:
                        yield (pdpte_value, vaddr, 0x40000000)
                    else:
                        yield (vaddr, 0x40000000)
                    continue
                #print "pdpte_value", hex(pdpte_value)
                pd_base = self.pdba_base(pdpte_value)
                pd = self.read_memory(pd_base, 0x200 * 8)
                if pd is None:
                    continue
                pd_entries = struct.unpack('<512Q', pd)
                for key in pd_entries:
                    if key == 0:
                        continue
                    #print bin(key), hex(key)
                prev_pd_entry = None
                for j in range(0, 0x200):
                    soffset = (j * 0x200 * 0x200 * 8)

                    entry = pd_entries[j]

                    if self.skip_duplicate_entries and entry == prev_pd_entry:
                        continue
                    prev_pd_entry = entry
                    if self.entry_present(entry) and self.page_size_flag(entry):
                        #print "entry1", hex(entry)
                        if with_pte:
                            yield (entry, vaddr + soffset, 0x200000)
                        else:
                            yield (vaddr + soffset, 0x200000)

                    elif self.entry_present(entry):
                        pt_base = entry & 0xFFFFFFFFFF000
                        pt = self.read_memory(pt_base, 0x200 * 8)
                        if pt is None:
                            continue
                        pt_entries = struct.unpack('<512Q', pt)
                        prev_pt_entry = None
                        for k in range(0, 0x200):
                            pt_entry = pt_entries[k]
                            if self.skip_duplicate_entries and pt_entry == prev_pt_entry:
                                continue
                            prev_pt_entry = pt_entry

                            if self.entry_present(pt_entry):
                                #print "entry2", hex(entry)
                                if with_pte:
                                    yield (pt_entry, vaddr + soffset + k * 0x1000, 0x1000)
                                else:
                                    yield (vaddr + soffset + k * 0x1000, 0x1000)

    def get_possible_pages(self, start_addr = 0x3809000, with_pte = False):
        '''
        This method generates a list of pages that are
        available within the address space. The entries in
        are composed of the virtual address of the page
        and the size of the particular page (address, size).
        It walks the 0x1000/0x8 (0x200) entries in each Page Map,
        Page Directory, and Page Table to determine which pages
        are accessible.
        '''
        pml_enrty = []
        pml_enrty2 = []
        step = 0
        while step < 0x10000:
            # read the full pml4
            pml4 = self.read_memory(start_addr+step & 0xffffffffff000, 0x200 * 8)
            if pml4 is None:
                continue

            # unpack all entries
            pml4_entries = struct.unpack('<512Q', pml4)
            for key in pml4_entries:
                if key == 0:
                    continue
                if not bin(key & 0b111111111111) == '0b1100111':
                    continue
                if len(bin(key)) > 32 or len(bin(key)) < 25:
                    continue
                #print bin(key), hex(key), hex(start_addr+step)

            for pml4e in range(0, 0x200):
                pml4e_value = pml4_entries[pml4e]
                if not self.entry_present(pml4e_value):
                    continue
                if not bin(pml4e_value & 0b111111111111) == '0b1100111':
                    continue
                if len(bin(pml4e_value)) > 32 or len(bin(pml4e_value)) < 25:
                    continue

                pdpt_base = (pml4e_value & 0xffffffffff000)
                pdpt = self.read_memory(pdpt_base, 0x200 * 8)
                if pdpt is None:
                    continue
                pdpt_entries = struct.unpack('<512Q', pdpt)
                for pdpte in range(0, 0x200):
                    vaddr = (pml4e << 39) | (pdpte << 30)
                    pdpte_value = pdpt_entries[pdpte]
                    if not self.entry_present(pdpte_value):
                        continue

                    if self.page_size_flag(pdpte_value):
                        if not hex(start_addr+step) in pml_enrty2:
                            pml_enrty2.append(hex(start_addr+step))
                        continue
                    #print "pdpte_value", hex(pdpte_value)
                    pd_base = self.pdba_base(pdpte_value)
                    pd = self.read_memory(pd_base, 0x200 * 8)
                    if pd is None:
                        continue
                    pd_entries = struct.unpack('<512Q', pd)
                    for key in pd_entries:
                        if key == 0:
                            continue
                        #print bin(key), hex(key)
                    prev_pd_entry = None
                    for j in range(0, 0x200):
                        soffset = (j * 0x200 * 0x200 * 8)

                        entry = pd_entries[j]

                        if self.skip_duplicate_entries and entry == prev_pd_entry:
                            continue
                        prev_pd_entry = entry
                        if self.entry_present(entry) and self.page_size_flag(entry):
                            if not hex(start_addr+step) in pml_enrty2:
                                pml_enrty2.append(hex(start_addr+step))

                        elif self.entry_present(entry):
                            pt_base = entry & 0xFFFFFFFFFF000
                            pt = self.read_memory(pt_base, 0x200 * 8)
                            if pt is None:
                                continue
                            pt_entries = struct.unpack('<512Q', pt)
                            prev_pt_entry = None
                            for k in range(0, 0x200):
                                pt_entry = pt_entries[k]
                                if self.skip_duplicate_entries and pt_entry == prev_pt_entry:
                                    continue
                                prev_pt_entry = pt_entry

                                if self.entry_present(pt_entry):
                                    if not hex(start_addr+step) in pml_enrty2:
                                        pml_enrty2.append(hex(start_addr+step))
                #print hex(key), "pml4e_value", hex(pml4e_value), hex(start_addr+step)
                if not hex(start_addr+step) in pml_enrty:
                    pml_enrty.append(hex(start_addr+step))
            step += 0x200 * 8

        pml_enrty.sort()
        pml_enrty2.sort()
        #print len(pml_enrty), len(pml_enrty2)
        return pml_enrty2

    @classmethod
    def address_mask(cls, addr):
        return addr & 0xffffffffffff

class ArmAddressSpace():
    """Address space for ARM processors"""

    order = 800
    pae = False
    paging_address_space = True
    checkname = 'ArmValidAS'
    minimum_size = 0x1000
    alignment_gcd = 0x1000
    _long_struct = struct.Struct("<I")

    def read_long_phys(self, addr):
        '''
        Returns an unsigned 32-bit integer from the address addr in
        physical memory. If unable to read from that location, returns None.
        '''
        try:
            string = self.base.read(addr, 4)
        except IOError:
            string = None
        if not string:
            return obj.NoneObject("Could not read_long_phys at offset " + hex(addr))
        longval, = self._long_struct.unpack(string)
        return longval

    def page_table_present(self, entry):
        if entry:
            return True # TODO FIXME
        return False

    # Page Directory Index (1st Level Index)
    def pde_index(self, vaddr):
        return (vaddr >> 20)

    # 1st Level Descriptor
    def pde_value(self, vaddr):
        return self.read_long_phys(self.dtb_paddr | (self.pde_index(vaddr) << 2))

    # 2nd Level Page Table Index (Course Pages)
    def pde2_index(self, vaddr):
        return ((vaddr >> 12) & 0x0FF)

    # 2nd Level Page Table Descriptor (Course Pages)
    def pde2_value(self, vaddr, pde):
        return self.read_long_phys((pde & 0xFFFFFC00) | (self.pde2_index(vaddr) << 2))

    # 2nd Level Page Table Index (Fine Pages)
    def pde2_index_fine(self, vaddr):
        return ((vaddr >> 10) & 0x3FF)

    # 2nd Level Page Table Descriptor (Fine Pages)
    def pde2_value_fine(self, vaddr, pde):
        return self.read_long_phys((pde & 0xFFFFF000) | (self.pde2_index_fine(vaddr) << 2))


    def get_pte(self, vaddr, pde_value):
        # page table
        if (pde_value & 0b11) == 0b00:
            # If bits[1:0] == 0b00, the associated modified virtual addresses are unmapped,
            # and attempts to access them generate a translation fault

            debug.debug("get_pte: invalid pde_value {0:x}".format(pde_value))
            return None

        elif (pde_value & 0b11) == 0b10:
            # If bits[1:0] == 0b10, the entry is a section descriptor for its associated modified virtual addresses.
            # If bit[18] is set, optional supersections are used, which we don't support yet

            issuper = int(pde_value & (1 << 18))

            if issuper:
                # TODO: Implement Supersection support if needed
                debug.warning("supersection found")
                return None
            else:
                return ((pde_value & 0xFFE00000) | (vaddr & 0x1FFFFF))

        elif (pde_value & 0b11) == 0b01:
            # If bits[1:0] == 0b01, the entry gives the physical address of a coarse second-level table, that specifies
            # how the associated 1MB modified virtual address range is mapped.
            pde2_value = self.pde2_value(vaddr, pde_value)

            if not pde2_value:
                debug.debug("no pde2_value", 4)
                return None

            if (pde2_value & 0b11) == 0b01:
                # 64K large pages
                return ((pde2_value & 0xFFFF0000) | (vaddr & 0x0000FFFF))
            elif (pde2_value & 0b11) == 0b10 or (pde2_value & 0b11) == 0b11:
                # 4K small pages
                return ((pde2_value & 0xFFFFF000) | (vaddr & 0x00000FFF))
            else:
                debug.warning("get_pte: invalid course pde2_value {0:x}".format(pde2_value))
                return None

        elif (pde_value & 0b11) == 0b11:
            # If bits[1:0] == 0b11, the entry gives the physical address of a fine second-level table. A fine
            # second-level page table specifies how the associated 1MB modified virtual address range is mapped.

            pde2_value = self.pde2_value_fine(vaddr, pde_value)

            if not pde2_value:
                debug.debug("no pde2_value", 4)
                return None

            if (pde2_value & 0b11) == 0b01:
                # 64K large pages
                return ((pde2_value & 0xFFFF0000) | (vaddr & 0x0000FFFF))
            elif (pde2_value & 0b11) == 0b10:
                # 4K small pages
                return ((pde2_value & 0xFFFFF000) | (vaddr & 0x00000FFF))
            elif (pde2_value & 0b11) == 0b11:
                #1k tiny pages
                return ((pde2_value & 0xFFFFFC00) | (vaddr & 0x3FF))
            else:
                debug.warning("get_pte: invalid fine pde2_value {0:x}".format(pde2_value))
                return None

    def vtop(self, vaddr):
        # Volatility only support ARM 32 bit.
        if vaddr & 0xffff800000000000 == 0xffff800000000000:
            paddr = vaddr - 0xffff800000000000 + 0x830
            return paddr
        else:
            return None

    # FIXME
    # this is supposed to return all valid physical addresses based on the current dtb
    # this (may?) be painful to write due to ARM's different page table types and having small & large pages inside of those
    def get_available_pages(self):

        for i in xrange(0, (2 ** 32) - 1, 4096):
            yield (i, 0x1000)
