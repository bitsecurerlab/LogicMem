/* This file contains recursive predicates */
:- use_module(library(clpfd)).
:- use_module(reif).
:- style_check(-singleton).

isTrue([X, Y]):-
    X == 49.

isTrue([X|Tail]):-
    isTrue(Tail).

log(File_name, Name, Addr, Base):-
    Offset #= Addr - Base,
    open(File_name, append, Stream),
    write(Stream, Name),
    write(Stream, ':'),
    write(Stream, Offset),
    nl(Stream),
    close(Stream).

possible_string_pointer(Base_addr) :-
    /* Verify if this pointer points to a stirng */
    string_val(Str),
    Str_profile = [
        [Name_addr, Name_val]
    ],
    tuples_in(Str_profile, Str),
    Name_addr #= Base_addr.

query_string_pointer(Val) :- 
    process_create(path('python'),
                    ['subquery.py', Val, "string_pointer"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_mount_struct(Base_addr, Offset) :-
    pointer(Ptr),
    Ptr_profile = ([
        [Mnt_devname_addr, Mnt_devname_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    Mnt_devname_addr #= Base_addr + Offset,
    labeling([enum], [Mnt_devname_addr, Mnt_devname_val]),
    query_string_pointer(Mnt_devname_val).

possible_kernel_param(Base_addr) :-
    string_val(Str),
    Str_profile = [
        [Name_addr, Name_val]
    ],
    tuples_in(Str_profile, Str),
    Name_addr #= Base_addr.

possible_in_device(Base_addr) :-
    /* in_ifaddr remains the same across kernel versions 
       but we need this query to find ip_ptr in net_device struct
    */
    /*
        struct net_device *dev;
        int               refcnt;
        int               dead;
        struct in_ifaddr  *ifa_list;
    */
    pointer(Ptr),
    int(Int),
    Ptr_profile = ([
        [Dev_addr, Dev_val],
        [Ifa_list_addr, Ifa_list_val]
    ]),
    Int_profile = ([
        [Refcnt_addr, Refcnt_val],
        [Dead_addr, Dead_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Int_profile, Int),
    Dead_addr #= Refcnt_addr + 4,
    chain([Dev_addr, Refcnt_addr, Dead_addr, Ifa_list_addr], #<),

    Dev_addr #= Base_addr,
    Ifa_list_addr #= Base_addr + 16,
    labeling([enum], [Ifa_list_addr, Ifa_list_val]),

    process_create(path('python'),
                    ['subquery.py', Ifa_list_val, "in_ifaddr"],
                    [stdout(pipe(In))]),
    print(In),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_in_ifaddr(Base_addr) :-
    /* in_ifaddr remains the same across kernel versions */
    pointer(Ptr),
    Ptr_profile = ([
        [Hash_addr, Hash_val],
        [Ifa_next_addr, Ifa_next_val],
        [Ifa_dev_addr, Ifa_dev_val],
        [Rcu_head_addr, Rcu_head_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    chain([Hash_addr, Ifa_next_addr, Ifa_dev_addr, Rcu_head_addr], #<),
    Hash_addr #= Base_addr,
    Ifa_next_addr #= Hash_addr + 16,
    Ifa_dev_addr #= Ifa_next_addr + 8,
    Rcu_head_addr #= Ifa_dev_addr + 8,
    labeling([enum], [Hash_addr, Ifa_next_addr, Ifa_dev_addr, Rcu_head_addr]).

possible_mm_struct(Current_addr) :- 
    statistics(real_time, [Start|_]),
    pointer(Ptr),
    long(Ulg),

    Ptr_profile = [
        [Mmap_addr, Mmap_val],
        [Pgd_addr, Pgd_val]  
    ],
    Ulong_profile = [
        [Mmap_base_addr, Mmap_base_val],
        [Task_size_addr, Task_size_val],
        [Start_brk_addr, Start_brk_val],
        [Brk_addr, Brk_val],
        [Start_stack_addr, Start_stack_val],
        [ARG_start_addr, ARG_start_val],
        [ARG_end_addr, ARG_end_val],
        [ENV_start_addr, ENV_start_val],
        [ENV_start_addr, ENV_start_val]
    ],
    Mmap_addr #= Current_addr,
    Mmap_base_val #> 0x7f0000000000,
    chain([Mmap_addr, Mmap_base_addr, Task_size_addr, Pgd_addr], #<),
    Pgd_addr #> Task_size_addr,
    Pgd_addr #=< Task_size_addr + 40,
    %FIXME: This rule may not be true for other mm_struct.
    Task_size_val #>= 0x7ffffffff000,

    Start_brk_addr #> Pgd_addr,
    Start_stack_val #> 0x7ff000000000,
    ARG_start_addr #< Current_addr + 500,
    ARG_end_addr #= ARG_start_addr + 8,
    ENV_start_addr #= ARG_end_addr + 8,
    ENV_end_addr #= ENV_start_addr + 8,
    chain([Start_brk_addr, Brk_addr, Start_stack_addr, ARG_start_addr], #<),
    ARG_start_addr #= Start_brk_addr + 24,
    Brk_val #< 0x7ff000000000,
    ARG_start_val #> 0x7ff000000000,
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Ulong_profile, Ulg),

    Mmap_val #> 0,
    Pgd_val #> 0,
    labeling([enum], [Mmap_addr, Mmap_val, Mmap_base_addr, Pgd_addr, Pgd_val]),
    
    process_create(path('python'),
                    ['subquery.py', Mmap_val, "vm_area_struct", Current_addr],
                    [stdout(pipe(In))]),
    
    print(In),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),
    label([Start_brk_addr, Brk_addr, Start_stack_addr, ARG_start_addr]),
    statistics(real_time, [End|_]),

    log("./profile/mm_struct", "mmap", Mmap_addr, Current_addr),
    log("./profile/mm_struct", "mmap_base", Mmap_base_addr, Current_addr),
    log("./profile/mm_struct", "pgd", Pgd_addr, Current_addr),
    log("./profile/mm_struct", "start_brk", Start_brk_addr, Current_addr),
    log("./profile/mm_struct", "brk", Brk_addr, Current_addr),
    log("./profile/mm_struct", "start_stack", Start_stack_addr, Current_addr),
    log("./profile/mm_struct", "arg_start", ARG_start_addr, Current_addr),
    log("./profile/mm_struct", "arg_end", ARG_end_addr, Current_addr),
    log("./profile/mm_struct", "env_start", ENV_start_addr, Current_addr),
    log("./profile/mm_struct", "env_end", ENV_end_addr, Current_addr),

    log("./profile/mm_struct", "mm_struct time", End, Start).

possible_mm_struct_arm(Current_addr) :-
    pointer(Ptr),
    long(Ulg),

    Ptr_profile = [
        [Mmap_addr, Mmap_val],
        [Pgd_addr, Pgd_val]  
    ],
    Ulong_profile = [
        [Mmap_base_addr, Mmap_base_val],
        [Task_size_addr, Task_size_val],
        [Start_brk_addr, Start_brk_val],
        [Brk_addr, Brk_val],
        [Start_stack_addr, Start_stack_val],
        [ARG_start_addr, ARG_start_val]
    ],
    Mmap_addr #= Current_addr,
    Mmap_base_val #> 0x7f00000000,
    chain([Mmap_addr, Mmap_base_addr, Task_size_addr, Pgd_addr], #<),
    Pgd_addr #> Task_size_addr,
    Pgd_addr #=< Task_size_addr + 40,
    %Not sure about this rule
    Task_size_val #>= 0x7f00000000,
    Start_brk_addr #> Pgd_addr,
    Start_stack_val #> 0x7f00000000,
    ARG_start_addr #< Current_addr + 500,
    chain([Start_brk_addr, Brk_addr, Start_stack_addr, ARG_start_addr], #<),
    ARG_start_addr #= Start_brk_addr + 24,
    Brk_val #< 0x7f00000000,
    ARG_start_val #> 0x7f00000000,
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Ulong_profile, Ulg),
    Mmap_val #> 0,
    Pgd_val #> 0,
    labeling([enum], [Mmap_addr, Mmap_val, Mmap_base_addr, Pgd_addr, Pgd_val]),
    label([Start_brk_addr, Brk_addr, Start_stack_addr, ARG_start_addr]),
    log("./profile/mm_struct", "mmap", Mmap_addr, Current_addr),
    log("./profile/mm_struct", "mmap_base", Mmap_base_addr, Current_addr),
    log("./profile/mm_struct", "task_size", Task_size_addr, Current_addr),
    log("./profile/mm_struct", "pgd", Pgd_addr, Current_addr),
    log("./profile/mm_struct", "start_brk", Start_brk_addr, Current_addr),
    log("./profile/mm_struct", "brk", Brk_addr, Current_addr),
    log("./profile/mm_struct", "start_stack", Start_stack_addr, Current_addr),
    log("./profile/mm_struct", "arg_start", ARG_start_addr, Current_addr),
    log("./profile/mm_struct", "mm_struct time", End, Start).


possible_vm_area_struct(Base_addr, MM_addr) :-
    statistics(real_time, [Start|_]),
    pointer(Ptr),
    long(Ulg),
    int(Int),
    Ptr_profile = [
        [VM_next_addr, VM_next_val],
        [Vm_mm_addr, Vm_mm_val],
        [VM_file_addr, VM_file_val]
    ],
    Ulong_profile = [
        [VM_start_addr, VM_start_val],
        [VM_end_addr, VM_end_val],
        [VM_flag_addr, VM_flag_val]
        /*VM_pgoff is 0, and we do not consider 0 as ulong*/
        %[VM_pgoff_addr, VM_pgoff_val]
    ],
    Int_profile = [
        [Vm_page_prot_addr, Vm_page_prot_val]
    ],
    VM_start_addr #>= Base_addr,
    chain([VM_start_addr, VM_end_addr, VM_next_addr, Vm_mm_addr, Vm_page_prot_addr, VM_flag_addr, VM_file_addr], #<),
    VM_end_addr #= VM_start_addr + 8,
    VM_next_addr #= VM_end_addr + 8,
    VM_next_addr #< Base_addr + 32,
    /* This is not always true */
    /*Vm_mm_val #= MM_addr,*/
    VM_file_addr #< Base_addr + 180,
    VM_pgoff_addr #= VM_file_addr - 8,
    VM_flag_addr #=< Vm_page_prot_addr + 8,
    /* Need to check this constraint, somehow makes no sense */
    %Vm_page_prot_val #> 0,
    /* The value constraints for vm_flag are not checked */
    /*VM_flag_val #< 0x88888888,
    VM_flag_val #> 0x8000000,*/
    VM_flag_val #< 0x88888888,
    VM_flag_val #> 0,
    VM_file_addr #< Base_addr + 200,

    tuples_in(Ptr_profile, Ptr),
    tuples_in(Ulong_profile, Ulg),
    tuples_in(Int_profile, Int),
    %FIXME: VM_flag may need value constraints.

    label([VM_next_addr, VM_next_val]),
    /* vm_file maybe zero */
    labeling([enum], [VM_start_addr, VM_end_addr, Vm_mm_addr, Vm_mm_val, VM_flag_addr, VM_pgoff_addr, VM_file_addr, VM_file_val]),
    
    VM_file_val #> 0,
    process_create(path('python'),
                ['subquery.py', VM_file_val, "vm_file"],
                [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),
    statistics(real_time, [End|_]),
    label([VM_flag_val]),

    log("./profile/vm_area_struct", "vm_start", VM_start_addr, Base_addr),
    log("./profile/vm_area_struct", "vm_end", VM_end_addr, Base_addr),
    log("./profile/vm_area_struct", "vm_next", VM_next_addr, Base_addr),
    log("./profile/vm_area_struct", "vm_mm", Vm_mm_addr, Base_addr),
    log("./profile/vm_area_struct", "vm_flag", VM_flag_addr, Base_addr),
    log("./profile/vm_area_struct", "vm_flag value", VM_flag_val, 0),
    log("./profile/vm_area_struct", "vm_pgoff", VM_pgoff_addr, Base_addr),
    log("./profile/vm_area_struct", "vm_file", VM_file_addr, Base_addr),
    log("./profile/vm_area_struct", "vm_area_struct time", End, Start).

check_vm_area_struct(Base_addr, Level) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "vm_area_struct", Level],
                    [stdout(pipe(In))]),
    print(In),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_vm_file(Base_addr) :-
    statistics(real_time, [Start|_]),
    pointer(Ptr),
    long(Ulg),
    Ptr_profile = [
        [Vfs_mount_addr, Vfs_mount_val],
        [Dentry_addr, Dentry_val],
        [F_op_addr, F_op_val]
    ],
    tuples_in(Ptr_profile, Ptr),
    Vfs_mount_addr #> Base_addr,
    Dentry_addr #= Vfs_mount_addr + 8,
    Dentry_addr #< Base_addr + 40,
    Vfs_mount_val #> 0,
    Dentry_val #> 0,
    F_op_addr #= Base_addr + 40, 
    F_op_val #> 0,
    chain([Vfs_mount_addr, Dentry_addr, F_op_addr], #<),
    labeling([enum], [Vfs_mount_val, Dentry_val, F_op_addr, F_op_val]),


    process_create(path('python'),
                    ['subquery.py', Vfs_mount_val, "vfs_mount"],
                    [stdout(pipe(NewIn))]),
    read_string(NewIn, Len, X),
    string_codes(X, Result),
    close(NewIn),
    isTrue(Result),
/*
    process_create(path('python'),
                    ['subquery.py', Dentry_val, "dentry"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),*/
    query_file_operation(F_op_val),
    statistics(real_time, [End|_]),

    log("./profile/file", "f_path", Vfs_mount_addr, Base_addr),
    log("./profile/file", "f_op", F_op_addr, Base_addr),
    log("./profile/file", "file time", End, Start).

query_file_operation(Base_addr) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "inode_operations"],
                    [stdout(pipe(NewIn))]),
    read_string(NewIn, Len, X),
    string_codes(X, Result),
    close(NewIn),
    isTrue(Result).

possible_name_pointer(Val, Name_offset) :-
    /* The value at val+name_offset is a string pointer */
    current_predicate(pointer/1),
    pointer(Ptr),
    Ptr_profile = ([
        [Name_addr, Name_val]
    ]),
    Name_addr #= Val + Name_offset,
    tuples_in(Ptr_profile, Ptr),
    labeling([enum], [Name_addr, Name_val]),
    query_string_pointer(Name_val).

possible_vfs_mount(Base_addr) :-
    pointer(Ptr),
    int(Int),
    Ptr_profile = [
        [Dentry_addr, Dentry_val],
        [Mnt_sb_addr, Mnt_sb_val]
    ],
    Int_profile = [
        [Mnt_flags_addr, Mnt_flags_val]
    ],
    
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Int_profile, Int),
    Dentry_addr #= Base_addr,
    Dentry_val #> 0,
    Mnt_flags_addr #= Dentry_addr + 16,
    Mnt_flags_val #>= 0,
    Mnt_sb_val #> 0,
    chain([Dentry_addr, Mnt_sb_addr, Mnt_flags_addr], #<),
    label([Dentry_addr, Dentry_val, Mnt_flags_addr, Mnt_flags_val]).
 
possible_dentry(Base_addr) :-
    /*
        struct dentry *d_parent;
        struct qstr d_name contains char *name; it's a name pointer
        struct inode *d_inode;
        unsigned char d_iname[LEN];
        const struct dentry_operations *d_op;
        struct list_head d_child;
        struct list_head d_subdirs;
        union {
	        struct hlist_node d_alias;
	        struct rcu_head d_rcu;
        } d_u;
    */
    statistics(real_time, [Start|_]),
    pointer(Ptr),
    string_val(Str),
    long(Ulg),
    Ptr_profile = [
        [Dparent_addr, Dparent_val],
        [Dname_addr, Dname_val],
        [D_inode_addr, D_inode_val],
        [D_op_addr, D_op_val],
        [Dchild_addr, Dchild_val],
        [D_subdirs_addr, D_subdirs_val]
    ],
    Str_profile = [
        [D_iname_addr, D_iname_val]
    ],
    Ulong_profile = [
        [Dname_len_addr, Dname_len_val]
    ],
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    tuples_in(Ulong_profile, Ulg),
    Dparent_addr #> Base_addr,
    Dname_addr #= Dname_len_addr + 8,
    chain([Dparent_addr, Dname_len_addr, Dname_addr, D_inode_addr, D_iname_addr, 
            D_op_addr, Dchild_addr, D_subdirs_addr], #<),
    D_subdirs_addr #= Dchild_addr + 16,
    D_subdirs_addr #< Base_addr + 200,
    Dparent_val #> 0,
    log("./profile/debug", "dentry", 0, 0),
    labeling([enum], [Dname_addr, Dname_val]),
    query_string_pointer(Dname_val),
    labeling([enum], [D_iname_addr, D_iname_val]),
    D_iname_offset #= D_iname_addr - Base_addr,
    Dname_offset #= Dname_addr - Base_addr,
    log("./profile/debug", "dentry2", 0, 0),
    labeling([enum], [Dparent_addr, Dparent_val]),
    Parent_dname #= Dparent_val + Dname_offset,
    process_create(path('python'),
                    ['subquery.py', Parent_dname, "name_pointer", 0],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),
    log("./profile/debug", "dentry3", Dname_offset, 0),

    labeling([enum], [D_inode_addr, D_inode_val]),
    query_inode(D_inode_val),
    /* d_op might be zero! */
    labeling([enum], [D_op_addr, D_op_val]),
    %query_file_operation(D_op_val),

    labeling([enum], [Dchild_addr, Dchild_val]),
    Dchild_offset #= Dchild_addr - Base_addr,
    Dchild_init #= Dchild_val - Dchild_offset,
    query_name_pointer(Dchild_init, Dname_offset),

    /* This can be hardcoded as d_child_addr + 16 */
    labeling([enum], [D_subdirs_addr, D_subdirs_val]),
    Dsubdirs_offset #= D_subdirs_addr - Base_addr,
    D_subdirs_init #= D_subdirs_val - Dsubdirs_offset,
    query_name_pointer(D_subdirs_init, Dname_offset),

    _Name_addr #= Dname_addr - 8,

    statistics(real_time, [End|_]),

    log("./profile/dentry", "parent", Dparent_addr, Base_addr),
    log("./profile/dentry", "d_name", _Name_addr, Base_addr),
    log("./profile/dentry", "d_inode", D_inode_addr, Base_addr),
    log("./profile/dentry", "D_inode_addr", D_inode_val, 0),
    log("./profile/dentry", "d_iname", D_iname_addr, Base_addr),
    log("./profile/dentry", "dchild", Dchild_addr, Base_addr),
    log("./profile/dentry", "d_subdirs", D_subdirs_addr, Base_addr),
    log("./profile/dentry", "dentry time", End, Start).

query_inode(Base_addr) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "inode"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_inode(Base_addr) :-
    /*
        struct inode_operations *i_op;
        struct super_block      *i_sb;
        struct address_space    *i_mapping;
    */
    statistics(real_time, [Start|_]),

    pointer(Ptr),
    long(Ulg),
    int(Int),
    /* Type Invariants */
    Ptr_profile = ([
        [I_op_addr, I_op_val],
        [I_sb_addr, I_sb_val],
        [I_mapping_addr, I_mapping_val],
        [I_fop_addr, I_fop_val],
        [I_flctx_addr, I_flctx_val]

    ]),
    Ulong_profile = ([
        /* i_mode is actually not long type. */
        [I_mode_addr, I_mode_val],
        [I_ino_addr, I_ino_val],
        [I_size_addr, I_size_val],
        [I_atime_addr, I_atime_val],
        [_I_atime_addr, _I_atime_val],
        [I_mtime_addr, I_mtime_val],
        [I_ctime_addr, I_ctime_val],
        [_I_ctime_addr, _I_ctime_val]
    ]),
    Int_profile = ([
        [I_uid_addr, I_uid_val],
        [I_gid_addr, I_gid_val],
        [_atomic_t_addr, _atomic_t_val],
        [_atomic_t2_addr, _atomic_t2_val]
    ]),    
    
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Ulong_profile, Ulg),
    tuples_in(Int_profile, Int),

    chain([I_mode_addr, I_uid_addr, I_gid_addr, I_op_addr, I_sb_addr, I_mapping_addr, I_ino_addr,
           I_size_addr, I_atime_addr, _I_atime_addr, I_mtime_addr, I_ctime_addr, _I_ctime_addr, 
           _atomic_t_addr, _atomic_t2_addr, I_fop_addr, I_flctx_addr], #<),

    I_mode_addr #= Base_addr,
    I_mode_val #> 0,
    I_gid_addr #= I_mode_addr + 8,
    I_op_addr #=< Base_addr + 32,
    I_op_val #> 0,
    I_fop_val #\= I_fop_addr,
    I_flctx_addr #= I_fop_addr + 8,
    I_flctx_val #\= I_flctx_addr,
    labeling([enum], [I_op_addr, I_op_val]),
    query_inode_operations(I_op_val),

    I_sb_addr #= I_op_addr + 8,
    I_mapping_addr #= I_sb_addr + 8,
    I_atime_addr #= I_size_addr + 8,
    I_mtime_addr #= I_atime_addr + 16,
    I_ctime_addr #= I_mtime_addr + 16,
    _I_ctime_addr #= I_ctime_addr + 8,
    I_size_val #> 0,
    I_atime_val #> 4096,
    I_mtime_val #> 4096,
    I_ctime_val #> 4096,
    I_fop_addr #< Base_addr + 400,
    labeling([enum], [I_sb_addr, I_mapping_addr, I_atime_addr, I_mtime_addr, I_ctime_addr]),
    I_fop_addr #= _atomic_t_addr + 8,
    labeling([enum], [I_fop_addr, I_fop_val]),
    I_fop_val #> 0,
    query_inode_operations(I_fop_val),

    statistics(real_time, [End|_]),
    log("./profile/inode", "I_mode_addr", I_mode_addr, Base_addr),
    log("./profile/inode", "I_uid_addr", I_uid_addr, Base_addr),
    log("./profile/inode", "I_gid_addr", I_gid_addr, Base_addr),
    log("./profile/inode", "I_op_addr", I_op_addr, Base_addr),
    log("./profile/inode", "I_sb_addr", I_sb_addr, Base_addr),
    log("./profile/inode", "I_mapping_addr", I_mapping_addr, Base_addr),
    log("./profile/inode", "I_size_addr", I_size_addr, Base_addr),
    log("./profile/inode", "I_atime_addr", I_atime_addr, Base_addr),
    log("./profile/inode", "I_mtime_addr", I_mtime_addr, Base_addr),
    log("./profile/inode", "I_ctime_addr", I_ctime_addr, Base_addr),
    log("./profile/inode", "I_fop_addr", I_fop_addr, Base_addr),
    log("./profile/inode", "inode time", End, Start).


query_inode_operations(Base_addr) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "inode_operations"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_name_pointer(Base_addr, Offset) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "name_pointer", Offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_inode_operations(Base_addr) :-
    /* a bunch of function pointers. */
    pointer(Ptr),
    Ptr_profile = ([
        [_L1_addr, _L1_val],
        [_L2_addr, _L2_val],
        [_L3_addr, _L3_val],
        [_L4_addr, _L4_val],
        [_L5_addr, _L5_val],
        [_L6_addr, _L6_val],
        [_L7_addr, _L7_val],
        [_L8_addr, _L8_val],
        [_L9_addr, _L9_val],
        [_L10_addr, _L10_val],
        [_L11_addr, _L11_val],
        [_L12_addr, _L12_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    chain([_L1_addr, _L2_addr, _L3_addr, _L4_addr, _L5_addr, _L6_addr, _L7_addr,
           _L8_addr, _L9_addr, _L10_addr, _L11_addr, _L12_addr], #<),
    _L1_addr #= Base_addr,
    _L12_addr #= Base_addr + 88.

query_module(Base_addr) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "module", Offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_module(Base_addr) :-
    /* struct list_head list;
       char name[LEN]; 
       struct kernel_param *kp;
       struct module_layout core_layout;
       struct module_layout init_layout; 
       unsigned int core_size, init_size;
       unsigned int init_text_size, core_text_size;
    */
    %get_time(Current),
    statistics(real_time, [Start|_]),
    pointer(Ptr),
    string_val(Str),
    int(Int),
    /* Type Invariants */
    Ptr_profile = ([
        [List_addr, List_val],
        [KP_addr, KP_val],
        [Core_base_addr, Core_base_val]
    ]),
    Str_profile = ([
        [Name_addr, Name_val]    
    ]),
    Int_profile = ([
        [Core_size_addr, Core_size_val],
        [Core_text_size_addr, Core_text_size_val],
        [RO_size_addr, RO_size_val],
        [RO_init_size_addr, RO_init_size_val]
    ]),    
    
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    tuples_in(Int_profile, Int),
    /* Order Invariants */
    chain([List_addr, Name_addr, KP_addr, Core_base_addr, Core_size_addr, 
            Core_text_size_addr, RO_size_addr, RO_init_size_addr], #<),
    RO_init_size_addr - Base_addr #< 1000,
    
    labeling([enum], [Name_addr, Name_val]),
    List_addr #= Name_addr - 16,
    labeling([enum], [List_addr, List_val]),
    Name_offset #= Name_addr - Base_addr,
    List_offset #= List_addr - Base_addr,
    query_list_head(List_val, Name_offset, List_offset),
    KP_val #> 0,
    labeling([enum], [KP_addr, KP_val]),
    query_kernel_param(KP_val),
    Core_size_addr #= Core_base_addr + 8,
    Core_size_val #> 0,
    Core_text_size_addr #= Core_size_addr + 4,
    Core_text_size_val #> 0,
    RO_size_addr #= Core_text_size_addr + 4,
    RO_init_size_addr #= RO_size_addr + 4,

    labeling([enum], [Core_base_addr, Core_size_addr, 
            Core_text_size_addr, RO_size_addr, RO_init_size_addr]),

    %get_time(End),
    statistics(real_time, [End|_]),
    %Time_past is End - Current,
    log("./profile/module", "base", Base_addr, 0),
    log("./profile/module", "list", List_addr, Base_addr),
    log("./profile/module", "name", Name_addr, Base_addr),
    log("./profile/module", "kp", KP_addr, Base_addr),
    log("./profile/module", "core_base", Core_base_addr, Base_addr),
    log("./profile/module", "core_size", Core_size_addr, Base_addr),
    log("./profile/module", "core_text_size", Core_text_size_addr, Base_addr),
    log("./profile/module", "module time", End, Start).

possible_d_entry(Base_addr, Dname_offset) :-
    current_predicate(string_val/1),
    string_val(Str),
    Str_profile = [
        [Dname_addr, Dname_val]
    ],
    Dname_addr #= Base_addr + Dname_offset,
    tuples_in(Str_profile, Str),
    label([Dname_addr]).

possible_list_head(Tasks_val, Comm_offset, Tasks_offset) :-
    string_val(Str),
    pointer(Ptr),
    Ptr_profile = [
        [Tasks_val, Tasks_addr]
    ],
    Str_profile = [
        [Comm_addr, Comm_val]
    ],
    Comm_addr #= Tasks_val - Tasks_offset + Comm_offset,
    Tasks_addr #\= Tasks_val,
    tuples_in(Str_profile, Str),
    tuples_in(Ptr_profile, Ptr),
    label([Comm_addr]).

possible_ts(Base_addr, Comm_offset, Tasks_offset) :-
    string_val(Str),
    pointer(Ptr),
    Ptr_profile = [
        [Tasks_addr, Tasks_val]
    ],
    Str_profile = [
        [Comm_addr, Comm_val]
    ],

    Comm_addr #= Base_addr + Comm_offset,
    Tasks_addr #= Base_addr + Tasks_offset,
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),

    label([Tasks_val]),
    
    process_create(path('python'),
                    ['subquery.py', Tasks_val, "list_head", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_cred(Base_addr) :-
    statistics(real_time, [Start|_]),

    int(Int),
    long(Ulg),
    Int_profile = [
        [Addr1, Val1],
        [Addr2, Val2],
        [Addr3, Val3],
        [Addr4, Val4],
        [Addr5, Val5],
        [Addr6, Val6],
        [Addr7, Val7],
        [Addr8, Val8],
        [Addr9, Val9]
    ],
    %FIXME For now, this rule is hard-coded because we do not consider 0 as a unsign long number. 
    %So that for cred whos val10 is 0, this rule does not apply.
    /*Ulong_profile = [
        [Addr10, Val10],
        [Addr11, Val11]
    ],*/
    Addr1 #> Base_addr,
    %chain([Addr1, Addr2, Addr3, Addr4, Addr5, Addr6, Addr7, Addr8, Addr9, Addr10, Addr11], #<),
    chain([Addr1, Addr2, Addr3, Addr4, Addr5, Addr6, Addr7, Addr8, Addr9], #<),
    Addr1 #= Base_addr + 4,
    Addr9 #= Addr1 + 32,
    %Addr11 #< Base_addr + 120,
    tuples_in(Int_profile, Int),
    %tuples_in(Ulong_profile, Ulg),
    statistics(real_time, [End|_]),
    labeling([enum], [Addr1, Addr2, Addr5, Addr6]),
    log("./profile/cred", "cred time", End, Start),
    log('./profile/cred', "uid", Addr1, Base_addr),
    log('./profile/cred', "gid", Addr2, Base_addr),
    log('./profile/cred', "euid", Addr5, Base_addr),
    log('./profile/cred', "egid", Addr6, Base_addr).

possible_fs_struct(Base_addr) :-
    statistics(real_time, [Start|_]),
    int(Int),
    pointer(Ptr),
    Int_profile = [
        [Addr1, Val1],
        [Addr2, Val2],
        [Addr3, Val3]
    ],
    Ptr_profile = [
        [Root_addr, Root_val],
        [Root_dentry_addr, Root_dentry_val],
        [PWD_addr, PWD_val]
    ],
    Addr1 #>= Base_addr,
    Root_dentry_addr #= Root_addr + 8,
    chain([Addr1, Addr2, Addr3, Root_addr, Root_dentry_addr, PWD_addr], #<),
    PWD_addr #= Root_addr + 16,
    PWD_addr #< Base_addr + 80,
    tuples_in(Int_profile, Int),
    tuples_in(Ptr_profile, Ptr),
    Root_val #> 0,
    PWD_val #> 0,
    label([Root_addr, Root_val, Root_dentry_addr, Root_dentry_val]),
    /* some times the dentry fields are zero, use vfs_mount instead */
    process_create(path('python'),
                    ['subquery.py', Root_val, "vfs_mount"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),
    /* FIXME d_child in dentyr might be zero. */
    /*query_dentry(Root_dentry_val),*/
    log("./profile/debug", "vfsmount", Root_addr, Base_addr),

    label([PWD_addr, PWD_val]),
    process_create(path('python'),
                    ['subquery.py', PWD_val, "vfs_mount"],
                    [stdout(pipe(NewIn))]),
    read_string(NewIn, Len, X),
    string_codes(X, Result),
    close(NewIn),
    isTrue(Result),

    statistics(real_time, [End|_]),
    log("./profile/fs_struct", "fs time", End, Start),
    log('./profile/fs_struct', "Root", Root_addr, Base_addr),
    log('./profile/fs_struct', "pwd", PWD_addr, Base_addr),
    log('./profile/fs_struct', "fs_struct time", End, Start).

possible_mount(Base_addr) :-
    /* struct hlist_head mnt_hash;
       struct mount *mnt_parent; 
       struct vfsmount mnt;
       struct list_head mnt_mounts;
       struct list_head mnt_child;
       struct list_head mnt_instance;
       const char *mnt_devname;
       struct list_head mnt_list;
    */
    statistics(real_time, [Start|_]),
    %get_time(Current),
    pointer(Ptr),
    string_val(Str),
    int(Int),
    /* Type Invariants */
    Ptr_profile = ([
        [Mnt_hash_addr, Mnt_hash_val],
        [Mnt_parent_addr, Mnt_parent_val],
        [Vfsmount_addr, Vfsmount_val],
        [Mnt_child_addr, Mnt_child_val],
        [Mnt_devname_addr, Mnt_devname_val],
        [Mnt_list_addr, Mnt_list_val]
    ]),
    Int_profile = ([
        [Mnt_flags_addr, Mnt_flags_val]
    ]),    
    
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Int_profile, Int),
    /* Order Invariants */
    chain([Mnt_hash_addr, Mnt_parent_addr, Vfsmount_addr, Mnt_flags_addr,
            Mnt_child_addr, Mnt_devname_addr, Mnt_list_addr], #<),
    Mnt_hash_addr #= Base_addr,
    /* mnt_hash_addr is a list_head */
    Mnt_parent_addr #> Base_addr + 8,
    Mnt_list_addr - Base_addr #< 200,
    labeling([enum], [Mnt_devname_addr, Mnt_devname_val]),
    query_string_pointer(Mnt_devname_val),
    Mnt_devname_offset #= Mnt_devname_addr - Base_addr,
    /* the offset from mnt_mounts to mnt_list remains the same, so it's safe to use fixed offsets. */
    Mnt_child_addr #= Mnt_devname_addr - 32,
    Mnt_list_addr #= Mnt_devname_addr + 8,
    Mnt_flags_addr #= Vfsmount_addr + 16,
    labeling([enum], [Mnt_child_addr, Mnt_list_addr, Vfsmount_addr, Vfsmount_val]),
    Vfsmount_val #>= 0,
    /* Here we can infer layout of dentry structure 
       Maybe need to infer using another dentry, somehow it may not be initialized. 
    */
    Vfsmount_addr #> 0,
    %query_dentry(Vfsmount_addr),

    labeling([enum], [Mnt_parent_addr, Mnt_parent_val]),
    /* To verify another mount struct, only one-level query, so it does not direct call query_mount recursively */
    
    query_mount_struct(Mnt_parent_val, Mnt_devname_offset),
    
    %get_time(End),
    %Time_past is End - Current,
    statistics(real_time, [End|_]),
    log("./profile/mount", "mnt_hash", Mnt_hash_addr, Base_addr),
    log("./profile/mount", "mnt_parent", Mnt_parent_addr, Base_addr),
    log("./profile/mount", "mnt_child", Mnt_child_addr, Base_addr),
    log("./profile/mount", "mnt_devname", Mnt_devname_addr, Base_addr),
    log("./profile/mount", "mnt_list", Mnt_list_addr, Base_addr),
    log("./profile/mount", "mount time", End, Start).

possible_neigh_table(Base_addr) :- 
    statistics(real_time, [Start|_]),
    /* nht at offset 464 */
    pointer(Ptr),
    Ptr_profile = ([
        [Nht_addr, Nht_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    Nht_addr #>= Base_addr + 440,
    Nht_addr #=< Base_addr + 512,
    %Nht_addr #=< Base_addr + 472,
    labeling([enum], [Nht_addr, Nht_val]),
    query_neigh_hash_table(Nht_val),
    statistics(real_time, [End|_]),
    log("./profile/neigh_table", "nht", Nht_addr, Base_addr),
    log("./profile/neigh_table", "neigh_table time", End, Start).


possible_neigh_hash_table(Base_addr) :-
    /* neighbour **hash_buckets */
    pointer(Ptr),
    Ptr_profile = ([
        [Hash_buckest_addr, Hash_buckets_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    Hash_buckest_addr #= Base_addr,
    %Hash_buckest_addr #=< Base_addr + 32,
    labeling([enum], [Hash_buckest_addr, Hash_buckets_val]),
    process_create(path('python'),
                    ['subquery.py', Hash_buckets_val, "hash_buckets"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),
    log("./profile/debug", "neigh_hash_table2", 0, 0).

possible_hash_buckets(Base_addr) :-
    /* hash_buckets is an array of neighbour pointer 
       note that not all element are non-zero
    */
    pointer(Ptr),
    Ptr_profile = ([
        [Neighbour_addr, Neighbour_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    Neighbour_addr #< Base_addr + 64,
    Neighbour_val #> 0,
    labeling([enum], [Neighbour_addr, Neighbour_val]),
    process_create(path('python'),
                    ['subquery.py', Neighbour_val, "neighbour"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_neighbour(Base_addr) :-
    statistics(real_time, [Start|_]),

    /* net_device *dev at offset 368 */
    pointer(Ptr),
    Ptr_profile = ([
        [Dev_addr, Dev_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    /*Dev_addr #>= Base_addr + 360,*/
    /* relax range constraint */
    Dev_addr #>= Base_addr + 312,
    Dev_addr #=< Base_addr + 376,
    labeling([enum], [Dev_addr, Dev_val]),
    log("./profile/debug", "dev", Dev_addr, Base_addr),
    process_create(path('python'),
                    ['subquery.py', Dev_val, "net_device"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),
    statistics(real_time, [End|_]),
    log("./profile/neighbour", "dev", Dev_addr, Base_addr),
    log("./profile/neighbour", "neighbour time", End, Start).

possible_net_device(Base_addr) :- 
    /*
        char             name[NAMSIZ];
        struct list_head dev_list;
        unsigned char    addr_len;
        unsigned int     promiscuity;
        struct in_device *ip_ptr;
    */
    statistics(real_time, [Start|_]),

    pointer(Ptr),
    string_val(Str),
    int(Int),
    /* Type Invariants */
    Ptr_profile = ([
        [Dev_list_addr, Dev_list_val],
        [_atalk_ptr_addr, _atalk_ptr_val],
        [IP_ptr_addr, IP_ptr_val],
        [_dn_ptr_addr, _dn_ptr_val],
        [_ip6_ptr_addr, _ip6_ptr_val],
        [Dev_addr_addr, Dev_addr_val]
    ]),
    Str_profile = ([
        [Name_addr, Name_val]
        /*broadcase could be zero 
        [Broad_cast_addr, Broad_cast_val]*/
    ]),
    Int_profile = ([
        [Promisc_addr, Promisc_val],
        [Addr_len_addr, Addr_len_val]
    ]),    
    
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    tuples_in(Int_profile, Int),
    /* Hard to determine offsets for addr_len and promisc */
    chain([Name_addr, Dev_list_addr, Addr_len_addr, Promisc_addr, 
           _atalk_ptr_addr, IP_ptr_addr, _dn_ptr_addr, _ip6_ptr_addr, Dev_addr_addr], #<),
    Name_addr #= Base_addr,
    Name_offset #= Name_addr - Base_addr,
    IP_ptr_addr #= _atalk_ptr_addr + 8,
    IP_ptr_addr #< Base_addr + 1000,
    _ip6_ptr_addr #= IP_ptr_addr + 16,
    


    /* dev_list offset can be hardcoded since it remains the same */
    Dev_list_addr #= Base_addr + 80,
    labeling([enum], [Name_addr, Dev_list_addr, Dev_list_val]),
    /* do not have a good constrain to narrow down ip_ptr, use its rough offset
       to reduce the search space. 
     */ 
    /* relax range constraint */
    IP_ptr_addr #>= Base_addr + 696,
    IP_ptr_addr #=< Base_addr + 776,
    IP_ptr_val #> 0,

    labeling([enum], [IP_ptr_addr, IP_ptr_val]),

    query_in_device(IP_ptr_val),
    %labeling([enum], [Dev_addr_addr, Dev_addr_val]),
    %query_string_pointer(Dev_addr_val),

    statistics(real_time, [End|_]),

    log("./profile/net_device", "name", Name_addr, Base_addr),
    log("./profile/net_device", "ip_ptr", IP_ptr_addr, Base_addr),
    log("./profile/net_device", "dev_list", Dev_list_addr, Base_addr),
    log("./profile/net_device", "net_device time", End, Start).

query_in_device(IP_ptr_val) :-
    process_create(path('python'),
                    ['subquery.py', IP_ptr_val, "in_device"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).


query_mount_struct(Val, Offset) :- 
    process_create(path('python'),
                    ['subquery.py', Val, "mount_struct", Offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_dentry(Dentry_val) :-
    process_create(path('python'),
                    ['subquery.py', Dentry_val, "dentry"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_neigh_hash_table(Base_addr) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "neigh_hash_table"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).
