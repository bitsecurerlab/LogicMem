from src import memoryReader as rm
#from program import *
from pyswip.core import *
from pyswip import *
import time, mmap, struct
import AddressSpaceARM as arm
class PrologQuery(rm.AddressSpace):
#class PrologQuery(arm.AddressSpaceARM):
    def __init__(self, image_path):
        #arm.AddressSpaceARM.__init__(self, image_path, 0, 0)
        rm.AddressSpace.__init__(self, image_path, 0, 0)

    def construct_kb(self, paddr, input_f, output_f):
        base_addr = paddr
        with open(output_f, 'w') as kb:
            kb.write(":- use_module(library(clpfd))." + "\n")
            kb.write(":- style_check(-singleton).\n")
        self.extract_info(base_addr, output_f)

        with open(output_f, 'a') as outfile:
            with open(input_f, 'r') as inputfile:
                outfile.write(inputfile.read())

    def start_query(self, paddr, query):
        self.log("construct kb \t- " + query)
        '''
            construct the knowledge base along with rules read from query_rules.pl
        '''
        self.construct_kb(paddr, "./knowledge/query_rules.pl", "./knowledge/test_query.pl")

        self.log("start query \t- " + query)
        p = Prolog()
        p.consult("./knowledge/test_query.pl")
        count = 0
        self.log("finish kb \t- " + query)
        current = time.time()
        query_cmd = "query_" + query + "(" + str(paddr) + ")"
        for s in p.query(query_cmd, catcherrors=False):
            count += 1
            if count:
                break

        print("count result:", count)
        print("total time:", query, time.time() - current)
        self.log("finish query \t- " + query)

def parse_profile():
    profile = {}
    with open('profile.txt', 'r') as p:
        line = p.readline()
        while line:
            line = line.strip('\n')
            content = line.split(':')
            if content[0] in profile.keys():
                #print content[0], "in profile"
                if not content[1] in profile[content[0]]:
                    profile[content[0]].append(content[1])
            else:
                #print content[0], "not in profile"
                profile.update({content[0] : [content[1]]})
            line = p.readline()

    keys = profile.keys()
    with open('final_profile', 'w') as output:
        for key in keys:
            #print key, profile[key]
            content = str(key) + '\t' + str(profile[key]) + "\n"
            output.write(content)

def generate_result():
    current_time = time.time()
    while time.time() - current_time < 500:
        pass
    parse_profile()
    print "profile saved in final_profile"


def test():
    prolog_query = PrologQuery(sys.argv[1])
    #prolog_query.find_string("kthreadd")
    #prolog_query.find_string("swapper")
    prolog_query.find_tasks(0x3e589408-3000)
    #openwrt
    #prolog_query.find_tasks(0x7040f78-3000)
    #lede
    #prolog_query.find_tasks(0x7058e68-3000)
    #prolog_query.find_tasks(0xed30ee0-3000)

def main():
    '''
        Initialize with image path
    '''
    prolog_query = PrologQuery(sys.argv[1])

    os.environ["IMAGE_PATH"] = sys.argv[1]
    print( os.environ["IMAGE_PATH"])
    image_name = os.path.basename(sys.argv[1])
    symbol_file = image_name + "_symbol_table"
    #prolog_query.parse_system_map(sys.argv[2])
    #print prolog_query.init_top_pgt_from_system_map, prolog_query.init_task_from_system_map
    if os.path.exists("profile"):
        os.system("rm -rf profile")
        os.system("mkdir profile")
    '''
    What global symbols are needed to start the logic inference?
    init_task
    init_fs -> dentry...
    init_files
    modules -> module
    mount_hashtable -> mount (*)
    file_systems -> file_system_type
    neigh_tables -> neigh_table (*)
    '''
    version_num = prolog_query.version.split('.')
    if int(version_num[0])<=4 and int(version_num[1])<18:
        query_cmd = ["init_task", "init_fs", "modules", "mount_hashtable", "neigh_tables", "iomem_resource",
                 "tcp4_seq_afinfo", "udp4_seq_afinfo", "tty_drivers", "proc_root"]
        query_cmd = ["init_fs", "init_task"]
        query_object = {"init_task": "task_struct", "init_fs": "fs_struct", "modules": "module", 
                    "mount_hashtable": "mount_hash",
                    "neigh_tables": "neigh_tables", "iomem_resource": "resource",
                    "tcp4_seq_afinfo": "tcp_seq_afinfo", "udp4_seq_afinfo": "udp_seq_afinfo",
                    "tty_drivers": "tty_driver",
                    "proc_root": "proc_dir_entry",
                    "idt_table": "gate_struct",
                    "module_kset": "kset",
                    "inet_sock": "inet_sock"}
    # after_4.18
    elif int(version_num[0])>=5 or (int(version_num[0])>=4 and int(version_num[1])>=18):
        query_cmd = ["init_task", "init_fs", "modules", "mount_hashtable", "neigh_tables", "iomem_resource",
                 "tcp4_seq_ops", "udp_seq_ops", "tty_drivers", "proc_root", "inet_sock"]
        query_cmd = ["init_fs", "init_task"]
        query_object = {"init_task": "task_struct", "init_fs": "fs_struct", "modules": "module", 
                    "mount_hashtable": "mount_hash",
                    "neigh_tables": "neigh_tables", "iomem_resource": "resource",
                    "tcp4_seq_ops": "seq_operations", "udp_seq_ops": "seq_operations",
                    "tty_drivers": "tty_driver",
                    "proc_root": "proc_dir_entry",
                    "idt_table": "gate_struct",
                    "module_kset": "kset",
                    "inet_sock": "inet_sock",
                    "init_mm": "mm_struct"}
    symbol_table = {}
    #Read symbol address from recovered symbole table
    with open(symbol_file, 'r') as symbol:
        content = symbol.read().split('\n')
        for item in content:
            tmp = item.split()
            if not len(tmp) == 3:
                continue
            if tmp[-1] in query_cmd:
                print("find", tmp[-1])
                if tmp[0].endswith('L'):
                    tmp[0] = tmp[0][:-1]
                symbol_table[tmp[-1]] = int(tmp[0], 16) + prolog_query.v_shift
    #Cannot find init_task symbol from recovered symbol table, call signature searching
    if 'init_task' not in symbol_table.keys():
        kthread_paddr = prolog_query.find_string('kthreadd\0')
        init_task = prolog_query.find_tasks(kthread_paddr - 3000)
        symbol_table["init_task"] = init_task + prolog_query.v_to_p_shift
        symbol_table["init_fs"] = 0xfffffff82294380
        query_cmd = ["init_task"]
        print("[Symbol]: init_task vaddr", hex(init_task+prolog_query.v_to_p_shift), "paddr", hex(init_task))
        print("[Symbol]: init_top_pgt vaddr:", hex(prolog_query.dtb+prolog_query.v_to_p_shift), "paddr:", hex(prolog_query.dtb))
        #symbol_table["init_task"] = 0x1e219700

    #symbol_table["inet_sock"] = 0xffff8c7a578a1c00
    for item in symbol_table.keys():
        print(item, symbol_table[item], hex(symbol_table[item]))

    for query in query_cmd:
        paddr = prolog_query.vtop(symbol_table[query])
        #print query, hex(paddr)
        if query == 'modules':
            addr = prolog_query.read_memory(int(paddr), 8)
            #module list is the second field in module object, so minus 0x8 to get the initial address
            paddr = prolog_query.vtop(struct.unpack("<Q", addr)[0]) - 0x8
            print("modules", hex(paddr))

        if query == "mount_hashtable":
            # mount_hashtable -> array of mount
            addr = prolog_query.read_memory(int(paddr), 8)
            paddr = prolog_query.vtop(struct.unpack("<Q", addr)[0])
            #run Volatility to find a mount struct
            #paddr = prolog_query.vtop(0xffff93477d0a0d10)
        if query == "neigh_tables":
            #This works for Linux kernel 3.19 and newer
            print(hex(paddr))
            #addr = prolog_query.read_memory(int(paddr)+8, 8)
            #paddr = prolog_query.vtop(struct.unpack("<Q", addr)[0])
            #paddr = 0x1ce7010
            pass
        if query == "tty_drivers":
            addr = prolog_query.read_memory(int(paddr), 8)
            paddr = prolog_query.vtop(struct.unpack("<Q", addr)[0])
            #tty_driver object remains unchanged. 168 is the object size.
            paddr -= 168
        if query == "idt_table":
            addr = prolog_query.read_memory(int(paddr), 8)
            paddr = prolog_query.vtop(struct.unpack("<Q", addr)[0])
        if query == "init_task":
            #paddr = 0x1e219700
            paddr = prolog_query.find_task_struct(paddr)
            print("task:", hex(paddr))

        prolog_query.start_query(int(paddr), query_object[query])

if __name__ == "__main__":
    main()
    #test()