import os
from constraint import *
import memoryReader as mr
import sys

class Query(mr.AddressSpace):
    def __init__(self, mem_path, dtb, verbose):
        super().__init__(mem_path, dtb=dtb, verbose=verbose)
        self.results = {}

    def order_constraint(self, *args):
        for index in range(len(args)-1):
            if not args[index][0] < args[index+1][0]:
                return False
        return True

    def vfsmount(self, mnt):
        '''
        offsets of fields in vfsmount can be hard-coded.
        '''
        problem = Problem()
        facts = self.extract_facts(mnt[1], 24, 0)
        if len(facts['pointers']) == 0 or len(facts['integers']) == 0:
            return False
        pointers = ['mnt_root', 'mnt_sb']
        integers = ['mnt_flags']
        problem.addVariables(pointers, facts['pointers'])
        problem.addVariables(integers, facts['integers'])
        problem.addConstraint(FunctionConstraint(self.order_constraint), ('mnt_root', 'mnt_sb', 'mnt_flags'))
        problem.addConstraint(lambda a, b=0: a[1] != b, ('mnt_root',))
        problem.addConstraint(lambda a, b=0: a[1] != b, ('mnt_sb',))
        problem.addConstraint(FunctionConstraint(self.dentry), ('mnt_root',))
        problem.addConstraint(lambda a, b=0: a[1] > b, ('mnt_flags',))

        solutions = problem.getSolutions()
        for item in solutions:
            for key in item.keys():
                if key not in self.results.keys():
                    self.results[key] = [item[key]]
                elif item[key] not in self.results[key]:
                    self.results[key].append(item[key])
        if len(solutions) > 0:
            return True
        else:
            return False

    def parent_struct(self, parent, name, name_ptr):
        '''
        check if there is a string at the same offset of the name field.
        if yes, consider the target object as a parent of the same type.
        for `dentry`, we utilize the fact that there is one string and one string pointer.
        '''
        facts = self.extract_facts(parent[1]+name[0], 16, 0)
        if len(facts['strings']) == 0:
            return False
        facts = self.extract_facts(parent[1]+name_ptr[0], 8, 0)
        if len(facts['pointers']) == 0:
            return False
        if self.string_pointer(facts['pointers'][0]):
            return True
        else:
            return False

    def string_pointer(self, target):
        '''
        check whether the pointer refers to a string.
        '''
        facts = self.extract_facts(target[1], 8, 0)
        if not facts:
            return False
        if len(facts['strings']) == 0:
            return False
        else:
            return True

    def dentry(self, dentry):
        '''
        TODO: d_op
        '''
        problem = Problem()
        facts = self.extract_facts(dentry[1], 256, 0)
        if len(facts['pointers']) == 0 or len(facts['strings']) == 0:
            return False
        pointers = ['d_parent', 'd_inode', 'd_name', 'd_child_next', 'd_child_prev',
                    'd_subdirs_next', 'd_subdirs_prev']
        # d_iname can be up to 40 bytes
        strings = ['d_iname']
        problem.addVariables(pointers, facts['pointers'])
        problem.addVariables(strings, facts['strings'])
        problem.addConstraint(FunctionConstraint(self.order_constraint),
                                                    ('d_parent', 'd_name', 'd_inode', 'd_iname', 'd_child_next',
                                                    'd_child_prev', 'd_subdirs_next', 'd_subdirs_prev'))
        problem.addConstraint(FunctionConstraint(self.parent_struct), ('d_parent', 'd_iname', 'd_name'))
        # dentry name contains `/`
        problem.addConstraint(lambda a, b='/': b in a[1], ('d_iname',))
        # d_name is the offset of the name field in qstr structure.
        problem.addConstraint(FunctionConstraint(self.string_pointer), ('d_name',))
        problem.addConstraint(FunctionConstraint(self.inode), ('d_inode',))
        problem.addConstraint(lambda a, b=0: a[1] != b, ('d_inode',))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('d_name', 'd_inode'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('d_child_next', 'd_child_prev'))
        problem.addConstraint(FunctionConstraint(self.list_head), ('d_child_next', 'd_child_prev', 'd_iname'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('d_inode', 'd_iname'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('d_child_prev', 'd_subdirs_next'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('d_subdirs_next', 'd_subdirs_prev'))
        problem.addConstraint(FunctionConstraint(self.list_head), ('d_subdirs_next', 'd_subdirs_prev', 'd_iname'))

        solutions = problem.getSolutions()
        for item in solutions:
            for key in item.keys():
                if key not in self.results.keys():
                    self.results[key] = [item[key]]
                elif item[key] not in self.results[key]:
                    self.results[key].append(item[key])
        if len(solutions) > 0:
            return True
        else:
            return False

    def inode(self, f_inode):
        return True

    def file_operations(self, f_op):
        problem = Problem()
        facts = self.extract_facts(f_op[1], 1024, 0)
        if not facts or len(facts['pointers']) == 0:
            return False
        pointers = ['owner']
        problem.addVariables(pointers, facts['pointers'])
        problem.addConstraint(lambda a, b=0: a[0] == b, ('owner',))
        problem.addConstraint(lambda a, b=0: a[1] != b, ('owner',))
        #problem.addConstraint(FunctionConstraint(self.module), ('owner',))

        solutions = problem.getSolutions()

        if len(solutions) > 0:
            return True
        else:
            return False

    def file_struct(self, vm_file):
        '''
        vm_file in vm_area_struct could be NULL
        TODO: f_op
        '''
        problem = Problem()
        facts = self.extract_facts(vm_file[1], 256, 0)
        if len(facts['pointers']) == 0:
            return False
        # f_inode was added after v3.8
        pointers = ['f_path_mnt', 'f_path_dentry', 'f_inode', 'f_op']
        problem.addVariables(pointers, facts['pointers'])
        problem.addConstraint(FunctionConstraint(self.order_constraint),
                                                ('f_path_mnt', 'f_path_dentry', 'f_inode', 'f_op'))
        problem.addConstraint(FunctionConstraint(self.vfsmount), ('f_path_mnt',))
        problem.addConstraint(FunctionConstraint(self.dentry), ('f_path_dentry',))
        #problem.addConstraint(FunctionConstraint(self.file_operations), ('f_op',))

        solutions = problem.getSolutions()
        for item in solutions:
            for key in item.keys():
                if key not in self.results.keys():
                    self.results[key] = [item[key]]
                elif item[key] not in self.results[key]:
                    self.results[key].append(item[key])
        if len(solutions) > 0:
            return True
        else:
            return False

    def vm_area_struct(self, mmap):
        problem = Problem()
        facts = self.extract_facts(mmap[1], 256, 0)
        if len(facts['pointers']) == 0 or len(facts['longs']) == 0 or len(facts['integers']) == 0:
            return False
        pointers = ['vm_next', 'vm_mm', 'vm_file']
        problem.addVariables(pointers, facts['pointers'])
        longs = ['vm_start', 'vm_end', 'rb_subtree_gap', 'vm_flags']
        problem.addVariables(longs, facts['longs'])
        #vm_pgoff should be long, but 0 is not considered long
        integers = ['vm_page_prot', 'vm_pgoff']
        problem.addVariables(integers, facts['integers'])

        problem.addConstraint(FunctionConstraint(self.order_constraint),
                                                    ('vm_start', 'vm_end', 'vm_next', 'rb_subtree_gap', 'vm_mm',
                                                    'vm_page_prot', 'vm_flags', 'vm_pgoff', 'vm_file'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('vm_start', 'vm_end'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('vm_end', 'vm_next'))
        problem.addConstraint(lambda a, b=0: a[1] != b, ('vm_next',))
        # rb_subtree_gap >= vm_start
        # this probably is not always true
        problem.addConstraint(lambda a, b: b[1] >= a[1], ('vm_start', 'rb_subtree_gap'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('rb_subtree_gap', 'vm_mm'))
        problem.addConstraint(lambda a, b=0: a[1] != b, ('vm_mm',))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('vm_mm', 'vm_page_prot'))
        # r/w/x bits match between vm_page_prot and vm_flags
        problem.addConstraint(lambda a, b: a[1]&0xf == b[1]&0xf, ('vm_page_prot', 'vm_flags'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('vm_page_prot', 'vm_flags'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('vm_pgoff', 'vm_file'))
        # vm_file can be NULL
        problem.addConstraint(FunctionConstraint(self.file_struct), ('vm_file',))

        solutions = problem.getSolutions()
        for item in solutions:
            for key in item.keys():
                if key not in self.results.keys():
                    self.results[key] = [item[key]]
                elif item[key] not in self.results[key]:
                    self.results[key].append(item[key])
        if len(solutions) > 0:
            return True
        else:
            return False

    def mm_test(self, mm):
        problem = Problem()
        facts = self.extract_facts(mm[1], 4096, 1)
        if len(facts['pointers']) == 0 or len(facts['longs']) == 0:
            return False
        pointers = ['mmap', 'pgd']
        problem.addVariables(pointers, facts['pointers'])
        longs = ['mmap_base', 'task_size', 'brk' ,'start_stack', 'arg_start', 'arg_end', 'env_start', 'env_end']
        problem.addVariables(longs, facts['longs'])
        problem.addConstraint(FunctionConstraint(self.order_constraint),
                                        ('mmap', 'mmap_base', 'task_size', 'pgd', 'brk', 'start_stack',
                                            'arg_start', 'arg_end', 'env_start', 'env_end'))
        problem.addConstraint(lambda a, b=0: a[0] == b,
                                        ('mmap',))
        problem.addConstraint(FunctionConstraint(self.vm_area_struct),
                                        ('mmap',))
        problem.addConstraint(lambda a, b=0x7f0000000000: a[1] > b,
                                        ('mmap_base',))
        problem.addConstraint(lambda a, b=0x7ffffffff000: a[1] == b,
                                        ('task_size',))
        problem.addConstraint(lambda a, b=0: a[1] != b,
                                        ('pgd',))
        problem.addConstraint(lambda a, b=0: a[1] & 0xfff == b,
                                        ('pgd',))
        problem.addConstraint(lambda a, b=0x7ff000000000: a[1] > b,
                                        ('start_stack',))
        problem.addConstraint(lambda a, b=0x7ff000000000: a[1] > b,
                                        ('arg_start',))
        problem.addConstraint(lambda a, b=0x7ff000000000: a[1] > b,
                                        ('arg_end',))
        problem.addConstraint(lambda a, b=0x7ff000000000: a[1] > b,
                                        ('env_start',))
        problem.addConstraint(lambda a, b=0x7ff000000000: a[1] > b,
                                        ('env_end',))

        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('brk', 'start_stack'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('start_stack', 'arg_start'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('arg_start', 'arg_end'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('env_start', 'env_end'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('arg_end', 'env_start'))
        #problem.addConstraint(lambda a, b=280: a[0] == b, ('start_stack', ))
        problem.addConstraint(lambda a, b=1024: a[0] < b,
                                        ('env_end', ))
        solutions = problem.getSolutions()
        for item in solutions:
            for key in item.keys():
                if key not in self.results.keys():
                    self.results[key] = [item[key]]
                elif item[key] not in self.results[key]:
                    self.results[key].append(item[key])
        if len(solutions) > 0:
            return True
        else:
            return False

    def mm_struct(self, mm):
        problem = Problem()
        facts = self.extract_facts(mm[1], 1024, 0)
        if len(facts['pointers']) == 0 or len(facts['longs']) == 0:
            return False
        pointers = ['mmap', 'pgd']
        problem.addVariables(pointers, facts['pointers'])
        longs = ['mmap_base', 'task_size', 'brk' ,'start_stack', 'arg_start', 'arg_end', 'env_start', 'env_end']
        problem.addVariables(longs, facts['longs'])
        problem.addConstraint(FunctionConstraint(self.order_constraint),
                                        ('mmap', 'mmap_base', 'task_size', 'pgd', 'brk', 'start_stack',
                                            'arg_start', 'arg_end', 'env_start', 'env_end'))
        problem.addConstraint(lambda a, b=0: a[0] == b,
                                        ('mmap',))
        #problem.addConstraint(FunctionConstraint(self.vm_area_struct),
        #                                ('mmap',))
        problem.addConstraint(lambda a, b=0x7f0000000000: a[1] > b,
                                        ('mmap_base',))
        problem.addConstraint(lambda a, b=0x7ffffffff000: a[1] == b,
                                        ('task_size',))
        problem.addConstraint(lambda a, b=0: a[1] != b,
                                        ('pgd',))
        problem.addConstraint(lambda a, b=0: a[1] & 0xfff == b,
                                        ('pgd',))
        problem.addConstraint(lambda a, b=0x7ff000000000: a[1] > b,
                                        ('start_stack',))
        problem.addConstraint(lambda a, b=0x7ff000000000: a[1] > b,
                                        ('arg_start',))
        problem.addConstraint(lambda a, b=0x7ff000000000: a[1] > b,
                                        ('arg_end',))
        problem.addConstraint(lambda a, b=0x7ff000000000: a[1] > b,
                                        ('env_start',))
        problem.addConstraint(lambda a, b=0x7ff000000000: a[1] > b,
                                        ('env_end',))

        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('brk', 'start_stack'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('start_stack', 'arg_start'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('arg_start', 'arg_end'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('env_start', 'env_end'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('arg_end', 'env_start'))
        #problem.addConstraint(lambda a, b=280: a[0] == b, ('start_stack', ))
        problem.addConstraint(lambda a, b=1024: a[0] < b,
                                        ('env_end', ))
        solutions = problem.getSolutions()

        for item in solutions:
            for key in item.keys():
                if key not in self.results.keys():
                    self.results[key] = [item[key]]
                elif item[key] not in self.results[key]:
                    self.results[key].append(item[key])
        if len(solutions) > 0:
            return True
        else:
            return False

    def list_head(self, task_next, task_prev, comm):
        #if comm[0] < task_next[0]:
        #    return False
        next_comm_addr = task_next[1] - task_next[0] + comm[0]
        prev_comm_addr = task_prev[1] - task_next[0] + comm[0]
        facts1 = self.extract_facts(next_comm_addr, 16, 0)
        facts2 = self.extract_facts(prev_comm_addr, 16, 0)

        if not facts1 or not facts2:
            return False
        elif len(facts1['strings']) > 0 and len(facts2['strings']) > 0:
            if facts1['strings'][0] != facts2['strings'][0]:
                return True
            else:
                return False
        else:
            return False

    def parent_task(self, parent, comm, tasks_next):
        facts = self.extract_facts(parent[1])
        if len(facts['strings']) == 0:
            return False
        tasks = []
        pointers = facts['pointers']
        for index in range(len(pointers)):
            if pointers[index][0] == tasks_next[0]:
                tasks.append(pointers[index])
                tasks.append(pointers[index+1])
        if not tasks:
            return False
        if not self.list_head(tasks[0], tasks[1], comm):
            return False

        parent_comm_addr = parent[1] + comm[0]
        parent_comm_value = self.extract_facts(parent_comm_addr, 16, 0)

        if len(parent_comm_value['strings']) > 0:
            return True
        else:
            return False

    def cred_struct(self, cred):
        facts = self.extract_facts(cred[1], 48, 0)
        if len(facts['integers']) == 0:
            return False
        #for item in facts['integers']:
        #    print(item)
        integers = ['uid', 'gid', 'suid', 'sgid', 'euid', 'egid']
        problem = Problem()
        problem.addVariables(integers, facts['integers'])
        problem.addConstraint(lambda a, b=4: a[0] == b,
                                        ('uid',))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 20,
                                        ('uid', 'egid'))
        problem.addConstraint(lambda a, b=48: a[0] < b,
                                        ('egid',))
        problem.addConstraint(FunctionConstraint(self.order_constraint),
                                        ('uid', 'gid', 'suid', 'sgid', 'euid', 'egid'))

        solutions = problem.getSolutions()
        for item in solutions:
            for key in item.keys():
                if key not in self.results.keys():
                    self.results[key] = [item[key]]
                elif item[key] not in self.results[key]:
                    self.results[key].append(item[key])
        if len(solutions) > 0:
            return True
        else:
            return False

    def fdtable_struct(self, fdt):
        facts = self.extract_facts(fdt[1], 40, 0)
        if len(facts['integers']) == 0 or len(facts['pointers']) == 0:
            return False
        integers = ['max_fds']
        pointers = ['fd', 'close_on_exec', 'open_fds', 'full_fds_bits']
        problem = Problem()
        problem.addVariables(integers, facts['integers'])
        problem.addVariables(pointers, facts['pointers'])
        problem.addConstraint(lambda a, b=0: a[0] == b, ('max_fds',))
        problem.addConstraint(FunctionConstraint(self.order_constraint),
                                    ('max_fds', 'fd', 'close_on_exec', 'open_fds', 'full_fds_bits'))
        problem.addConstraint(lambda a, b=8: a[0] == b, ('fd',))
        problem.addConstraint(lambda a, b=0: a[1] != b, ('fd',))
        problem.addConstraint(lambda a, b=8: b[0] == a[0] + 24, ('fd', 'full_fds_bits'))
        problem.addConstraint(lambda a, b=0: a[1] != b, ('close_on_exec',))
        problem.addConstraint(lambda a, b=0: a[1] != b, ('open_fds',))
        problem.addConstraint(lambda a, b=0: a[1] != b, ('full_fds_bits',))


        solutions = problem.getSolutions()
        for item in solutions:
            for key in item.keys():
                if key not in self.results.keys():
                    self.results[key] = [item[key]]
                elif item[key] not in self.results[key]:
                    self.results[key].append(item[key])
        if len(solutions) > 0:
            return True
        else:
            return False

    def files_struct(self, files):
        '''
        no field change, offsets can be hard-coded.
        '''
        facts = self.extract_facts(files[1], 256, 0)
        if len(facts['integers']) == 0 or len(facts['pointers']) == 0 or len(facts['longs']) == 0:
            return False
        integers = ['count']
        problem = Problem()
        problem.addVariables(integers, facts['integers'])
        problem.addConstraint(lambda a, b=0: a[0] == b, ('count',))
        pointers = ['fdt', 'fd_array']
        problem.addVariables(pointers, facts['pointers'])
        longs = ['full_fds_bits_init']
        problem.addVariables(longs, facts['longs'])
        problem.addConstraint(FunctionConstraint(self.order_constraint),
                                        ('count', 'fdt', 'full_fds_bits_init', 'fd_array'))
        problem.addConstraint(lambda a, b=32: a[0] == 32, ('fdt', ))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('full_fds_bits_init', 'fd_array'))
        problem.addConstraint(FunctionConstraint(self.fdtable_struct), ('fdt',))

        solutions = problem.getSolutions()
        for item in solutions:
            for key in item.keys():
                if key not in self.results.keys():
                    self.results[key] = [item[key]]
                elif item[key] not in self.results[key]:
                    self.results[key].append(item[key])
        if len(solutions) > 0:
            return True
        else:
            return False

    def task_struct(self, base_addr, recursive=1):
        """Constraints for task_struct.

        Args:
            base_addr: address of a task_struct

        Returns:
            a set of valid candidate
        TODO:
        Recursive evaluate more processes (if not all) in the process list, which tolerants the changes of live memory
        """
        problem = Problem(BacktrackingSolver())
        facts = self.extract_facts(base_addr, 4096, 0)

        pointers = ['mm', 'active_mm', 'tasks_next', 'tasks_prev', 'parent', 'real_parent',
                    'child', 'group_leader', 'real_cred', 'cred', 'files']
        problem.addVariables(pointers, facts['pointers'])

        strings = ['comm']
        problem.addVariables(strings, facts['strings'])

        integers = ['pid', 'tgid']
        problem.addVariables(integers, facts['integers'])

        problem.addConstraint(FunctionConstraint(self.order_constraint),
                                        ('tasks_next', 'tasks_prev', 'mm', 'active_mm', 'pid',
                                        'tgid', 'parent', 'real_parent', 'child', 'group_leader',
                                        'real_cred', 'cred', 'comm', 'files'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8,
                                        ('mm', 'active_mm'))
        problem.addConstraint(lambda a, b=1000: a[0] > b,
                                        ('active_mm',))
        problem.addConstraint(lambda a, b=0: a[1] != b,
                                        ('mm',))
        problem.addConstraint(lambda a, b=0: a[1] != b,
                                        ('active_mm',))

        problem.addConstraint(FunctionConstraint(self.mm_struct), ('mm',))
        problem.addConstraint(FunctionConstraint(self.mm_struct), ('active_mm',))

        problem.addConstraint(lambda a, b: a[0] > b[0]-100,
                                        ('tasks_next', 'active_mm'))
        problem.addConstraint(lambda a, b=0: a[1] != b,
                                        ('tasks_next',))
        problem.addConstraint(lambda a, b=0: a[1] != b,
                                        ('tasks_prev',))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8,
                                        ('tasks_next', 'tasks_prev'))
        problem.addConstraint(FunctionConstraint(self.list_head),
                                        ('tasks_next', 'tasks_prev', 'comm'))
        problem.addConstraint(lambda a, b=0: a[1] != b,
                                        ('parent',))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8,
                                        ('parent', 'real_parent'))
        problem.addConstraint(lambda a, b=0: a[1] != b,
                                        ('real_parent',))
        problem.addConstraint(FunctionConstraint(self.parent_task),
                                        ('parent', 'comm', 'tasks_next'))
        problem.addConstraint(FunctionConstraint(self.parent_task),
                                        ('real_parent', 'comm', 'tasks_next'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8,
                                        ('real_parent', 'child'))
        problem.addConstraint(lambda a, b: b[0] <= a[0] + 32,
                                        ('child', 'group_leader'))
        problem.addConstraint(FunctionConstraint(self.parent_task),
                                        ('group_leader', 'comm', 'tasks_next'))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8,
                                        ('real_cred', 'cred'))
        problem.addConstraint(lambda a, b=2: len(a[1]) > b,
                                        ('comm', ))
        problem.addConstraint(FunctionConstraint(self.cred_struct),
                                        ('real_cred',))
        problem.addConstraint(FunctionConstraint(self.cred_struct),
                                        ('cred',))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 4,
                                        ('pid', 'tgid'))
        problem.addConstraint(lambda a, b=0: a[1] > b,
                                        ('pid',))
        problem.addConstraint(lambda a, b: b[1] == a[1],
                                        ('pid', 'tgid'))
        problem.addConstraint(lambda a, b=0: a[1] != b, ('files',))
        problem.addConstraint(FunctionConstraint(self.files_struct), ('files', ))

        solutions = problem.getSolutions()
        for item in solutions:
            for key in item.keys():
                if key not in self.results.keys():
                    self.results[key] = [item[key]]
                elif item[key] not in self.results[key]:
                    self.results[key].append(item[key])
            print(item)
        for key in self.results.keys():
            print(key, self.results[key])

    def kparam_string(self, kparam_str):
        facts = self.extract_facts(kparam_str[1], 16, 0)
        if len(facts['pointers']) > 1:
            if self.string_pointer(facts['pointers'][1]):
                return True
        elif len(facts['pointers']) == 1:
            if self.string_pointer(facts['pointers'][0]):
                return True
        return False

    def kernel_param(self, kp):
        facts = self.extract_facts(kp[1], 128, 0)
        if len(facts['pointers']) == 0:
            return False
        problem = Problem()
        pointers = ['name', 'mod', 'ops', 'str', 'arr']
        problem.addVariables(pointers, facts['pointers'])
        problem.addConstraint(FunctionConstraint(self.order_constraint), ('name', 'mod', 'ops', 'str', 'arr'))
        problem.addConstraint(lambda a, b=0: a[0] == b, ('name',))
        problem.addConstraint(FunctionConstraint(self.string_pointer), ('name',))
        problem.addConstraint(lambda a, b=0: a[1] != b, ('mod',))
        problem.addConstraint(lambda a, b=0: a[1] != b, ('ops',))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 16, ('name', 'ops'))

        problem.addConstraint(FunctionConstraint(self.kparam_string), ('str',))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('str', 'arr'))
        problem.addConstraint(lambda a, b=0: a[1] != b, ('arr',))

        solutions = problem.getSolutions()
        for item in solutions:
            print(item)
        if len(solutions) > 0:
            return True
        else:
            return False

    def kobject(self, target):
        '''
        TODO: add more fields
        '''
        problem = Problem()
        facts = self.extract_facts(target[1], 128, 0)
        if not facts or len(facts['pointers']) == 0:
            return False
        pointers = ['name']
        problem.addVariables(pointers, facts['pointers'])
        problem.addConstraint(lambda a, b=0: a[0] == b, ('name',))
        problem.addConstraint(FunctionConstraint(self.string_pointer), ('name',))
        solutions = problem.getSolutions()
        if len(solutions) > 0:
            return True
        else:
            return False

    def module(self, base_addr):
        '''
        TODO: add constraints for linux before v4.5
        '''
        problem = Problem()
        facts = self.extract_facts(base_addr[1], 1024, 0)
        if not facts:
            return False
        if len(facts['pointers']) == 0 or len(facts['strings']) == 0:
            return False

        pointers = ['list_next', 'list_prev', 'srcversion', 'holders_dir']
        strings = ['name']
        #integers = ['core_layout_size', 'core_layout_text_size', 'core_layout_ro_size', 'core_layout_ro_after_init_size',
        #            'init_layout_size', 'init_layout_text_size', 'init_layout_ro_size', 'init_layout_ro_after_init_size']

        problem.addVariables(pointers, facts['pointers'])
        problem.addVariables(strings, facts['strings'])
        #problem.addVariables(integers, facts['integers'])
        problem.addConstraint(FunctionConstraint(self.order_constraint),
                                        ('list_next', 'list_prev', 'name', 'srcversion', 'holders_dir'))
        problem.addConstraint(lambda a, b=256: a[0] < b, ('holders_dir',))
        problem.addConstraint(FunctionConstraint(self.list_head), ('list_next', 'list_prev', 'name'))
        problem.addConstraint(FunctionConstraint(self.string_pointer), ('srcversion',))
        problem.addConstraint(lambda a, b: b[0] == a[0] + 8, ('srcversion', 'holders_dir'))
        problem.addConstraint(FunctionConstraint(self.kobject), ('holders_dir',))

        # kp could be NULL
        #problem.addConstraint(FunctionConstraint(self.kernel_param), ('kp',))
        #problem.addConstraint(lambda a, b=264: a[0] == b, ('kp',))

        solutions = problem.getSolutions()
        for item in solutions:
            print(item)
        if len(solutions) > 0:
            return True
        else:
            return False

def test():
    problem = Problem()
    f = ['field_a', 'field_b']
    problem.addVariables(f, pointer_field)
    #problem.addVariable('field_a', pointer_field)
    #problem.addVariable('field_b', pointer_field)
    problem.addConstraint(lambda a, b: a[0] < b[0],
                            ("field_a", "field_b"))
    problem.addConstraint(lambda a, b: a[1] > b[1],
                            ("field_a", "field_b"))
    solutions = problem.getSolutions()
    print(solutions)
    #for item in solutions:
    #    print(item['field_a'])

def main():
    mem_path = sys.argv[1]
    #addr_space = mr.AddressSpace(mem_path, 0x50a0a000)
    query = Query(mem_path, 0, 0)
    image_name = os.path.basename(sys.argv[1])
    symbol_file = image_name + "_symbol_table"
    query_cmd = ["init_task"]
    query_object = {"init_task": "task_struct", "init_fs": "fs_struct", "modules": "module",
                    "mount_hashtable": "mount_hash",
                    "neigh_tables": "neigh_tables", "iomem_resource": "resource",
                    "tcp4_seq_afinfo": "tcp_seq_afinfo", "udp4_seq_afinfo": "udp_seq_afinfo",
                    "tty_drivers": "tty_driver",
                    "proc_root": "proc_dir_entry",
                    "idt_table": "gate_struct",
                    "module_kset": "kset",
                    "inet_sock": "inet_sock"}
    #query.extract_facts(0x17539c00, 8, 1)
    #return
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
                symbol_table[tmp[-1]] = int(tmp[0], 16) + query.kaslr_shift_vtov
    print(symbol_table)
    for cmd in query_cmd:
        paddr = query.vtop(symbol_table[cmd])
        if cmd == 'init_task':
            paddr = query.find_next_task(paddr)
            query.extract_facts(0x1a511680, 2048, 0)
            query.task_struct(paddr)
        elif cmd == 'modules':
            paddr = query.find_next_module(paddr)
            query.module([0, paddr])
    #print(hex(query.vtop(0xffffffff98e104c0+query.kaslr_shift_vtov)))
    #facts = addr_space.extract_facts(1352742720)
    #facts = addr_space.extract_facts(0x12b37b138-1256-16, 4096, 0)
    #facts = query.extract_facts(0x1bda08a0-2192-16, 4096, 1)
    # task struct
    #query.extract_facts(0x1bda08a0-2192-16, 4096, 1)
    # mm_struct
    #query.extract_facts(0x1eefc7c0, 4096, 1)
    # cred
    #query.extract_facts(0x1edec000, 4096, 1)
    #query.extract_facts(0x1505a448, 1024, 1)
    #facts = query.extract_facts(0x1bda71b0-1904, 4096, 1)
    #problem = Problem(BacktrackingSolver())
    #query.task_struct(0x12b37b138-1256-16)
    #query.test(0x1bda08a0-2192-16)

    #query.task_struct(0x1bda08a0-2192-16)
    #query.mm_struct([0, 0x1eefc7c0])
    #query.cred_struct([0, 0x1edec000])
    #for item in facts['pointers']:
    #    print(item)
    #query.files_struct([0, 0x1bd9c2c0])
    #query.vm_area_struct([0, 0x1edecd80])
    #query.dentry([0, 0x18dc96c0])

    #task_addr = query.find_next_task(query.vtop(0xffffffff98e104c0+query.kaslr_shift_vtov))
    #print(hex(task_addr))
    #module_addr = query.find_next_module(query.vtop(0xffffffff98e88ef0+query.kaslr_shift_vtov))
    #print(hex(module_addr))
    #query.module(module_addr)



if __name__ == "__main__":
    main()

