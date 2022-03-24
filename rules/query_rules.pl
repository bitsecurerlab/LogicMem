:- use_module(library(clpfd)).


isTrue([X, _]):-
    X == 49.

isTrue([_|Tail]):-
    isTrue(Tail).

log(File_name, Name, Addr, Base):-
    Offset #= Addr - Base,
    open(File_name, append, Stream),
    write(Stream, Name),
    write(Stream, ':'),
    write(Stream, Offset),
    nl(Stream),
    close(Stream).

print_time(Name, Start_time) :-
    get_time(Now),
    Time_past is Now - Start_time,
    print_nl(Name, Time_past).

start_query(Base_addr) :- 
    pointer(Ptr),
    string_val(Str),
    Ptr_profile = ([
        [MM2_addr, MM2_val],
        [Real_parent_addr, Real_parent_val],
        [Cred_addr, Cred_val],
        [FS_struct_addr, FS_struct_val]
    ]),
    Str_profile = ([
        [Comm_addr, Comm_val]    
    ]),
    chain([MM2_addr, Real_parent_addr, Cred_addr, Comm_addr, FS_struct_addr], #<),
    Real_parent_addr #> Comm_addr - 500,
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    labeling([enum], [Real_parent_addr, Real_parent_val,  Comm_addr, Comm_val]),
    process_create(path('python'),
                ['subquery.py', Real_parent_val, "task_struct"],
                [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_test(Base_addr) :-
    statistics(real_time, [Start|_]),
    get_time(Current),
    %current_predicate(string_val/1),
    pointer(Ptr),
    string_val(Str),
    int(Int),
    Ptr_profile = ([
        [MM_addr, MM_val],
        [MM2_addr, MM2_val],
        [Tasks_addr, Tasks_val],
        [Parent_addr, Parent_val],
        [Real_parent_addr, Real_parent_val],
        [Child_addr, Child_val],
        [Group_leader_addr, Group_leader_val],
        [Thread_group_addr, Thread_group_val],
        [Real_cred_addr, Real_cred_val],
        [Cred_addr, Cred_val]
    ]),
    Str_profile = ([
        [Comm_addr, Comm_val]    
    ]),
    Int_profile = ([
        [Pid_addr, Pid_val],
        [Tgid_addr, Tgid_val]    
    ]),
    chain([Tasks_addr, MM_addr, MM2_addr, Pid_addr, Tgid_addr, Real_parent_addr, Parent_addr , Child_addr, 
           Group_leader_addr, Thread_group_addr, Real_cred_addr, Cred_addr, Comm_addr], #<),
    Tasks_addr #> Base_addr,
    Comm_addr #= Base_addr + 968,
    Tasks_addr #= Base_addr + 544,
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    tuples_in(Int_profile, Int),
    labeling([enum], [Tasks_addr, Tasks_val, Comm_addr, Comm_val]),
    Comm_offset #= Comm_addr - Base_addr,
    Tasks_offset #= Tasks_addr - Base_addr,
    Tasks_val #> 0,
    query_list_head(Tasks_val, Comm_offset, Tasks_offset).


query_task_struct(Base_addr) :-
    statistics(real_time, [Start|_]),
    get_time(Current),
    current_predicate(string_val/1),
    pointer(Ptr),
    string_val(Str),
    int(Int),
    Ptr_profile = ([
        [MM_addr, MM_val],
        [MM2_addr, MM2_val],
        [Tasks_addr, Tasks_val],
        [Tasks2_addr, Tasks2_val],
        [Parent_addr, Parent_val],
        [Real_parent_addr, Real_parent_val],
        [Child_addr, Child_val],
        [Group_leader_addr, Group_leader_val],
        [Thread_group_addr, Thread_group_val],
        [Real_cred_addr, Real_cred_val],
        [Cred_addr, Cred_val],
        [Fs_struct_addr, Fs_struct_val],
        [Files_addr, Files_val]
    ]),
    Str_profile = ([
        [Comm_addr, Comm_val]    
    ]),
    Int_profile = ([
        [Pid_addr, Pid_val],
        [Tgid_addr, Tgid_val]    
    ]),
    
    %MM2_addr #> Base_addr + 1000,
    MM2_addr #= MM_addr + 8,
    MM2_val #> 0,
    Tasks_addr #> MM2_addr - 100,
    Tasks2_addr #= Tasks_addr + 8,

    Tgid_addr #= Pid_addr + 4,
    Real_parent_addr #< Tgid_addr + 20,
    Real_parent_addr #= Parent_addr - 8,
    Child_addr #= Parent_addr + 8,
    %FIXME This may be too strong
    %Children next and prev 16 
    %Sibling next and prev  16
    Group_leader_addr #=< Child_addr +32,
    Cred_addr #= Real_cred_addr + 8,
    /*MM2_addr #= Base_addr + 1992,
    Comm_addr #= Base_addr + 1656,
    Tasks_addr #= Base_addr + 1904,*/
    %Comm_addr #= Base_addr + 1696,
    %Tasks_addr #= Base_addr + 960,
    Files_addr #< Comm_addr + 200,
    Files_addr #= FS_struct_addr + 8,
    FS_struct_val #> 0,
    chain([Tasks_addr, Tasks2_addr, MM_addr, MM2_addr, Pid_addr, Tgid_addr, Real_parent_addr, Parent_addr , Child_addr, 
           Group_leader_addr, Thread_group_addr, Real_cred_addr, Cred_addr, Comm_addr, Fs_struct_addr, Files_addr], #<),

    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    tuples_in(Int_profile, Int),
    %print_time('before label mm', Current),

    label([MM2_addr, MM2_val]),
    label([MM_addr, MM_val]),
    %print_time('after label mm', Current),
    %query_mm_struct_arm(MM2_val),
    query_mm_struct(MM2_val),
    %print_time('after query mm', Current),

    labeling([], [Tasks_addr, Tasks_val, Comm_addr, Comm_val, Pid_addr, Tgid_addr]),

    Comm_offset #= Comm_addr - Base_addr,
    Tasks_offset #= Tasks_addr - Base_addr,
    Tasks_val #> 0,
    query_list_head(Tasks_val, Comm_offset, Tasks_offset),
    %print_time('after query list_head', Current),
    

    labeling([enum], [Tasks2_addr, Tasks2_val]),

    labeling([enum], [Real_parent_addr, Real_parent_val, Group_leader_addr, Group_leader_val, Child_addr, Child_val]),
    Real_parent_val #> 0,
    Group_leader_val #> 0,
    query_ts(Real_parent_val, Comm_offset, Tasks_offset),
    %print_time('after query ts1', Current),
    %query_list_head(Child_val-16, Comm_offset, Tasks_offset),
    %query_ts(Group_leader_val, Comm_offset, Tasks_offset),
    %print_time('after query ts2', Current),

    labeling([enum], [Real_cred_addr, Real_cred_val, Cred_addr, Cred_val]),
    Cred_val #> 0,
    %query_cred(Real_cred_val),
    %print_time('after query cred1', Current),
    %query_cred(Cred_val),
    %print_time('after query cred2', Current),


    label([Fs_struct_addr, Fs_struct_val, Files_addr, Files_val]),
    query_fs_struct(Fs_struct_val),

    get_time(Now),
    Time_past is Now - Current,
    statistics(real_time, [End|_]),

    MM_offset #= MM2_addr - Base_addr,
    Real_parent_offset #= Real_parent_addr - Base_addr,
    Group_leader_offset #= Group_leader_addr - Base_addr,
    log("./profile/task_struct", "tasks", Tasks_addr, Base_addr),
    log("./profile/task_struct", "mm", MM_addr, Base_addr),
    log("./profile/task_struct", "active_mm", MM2_addr, Base_addr),
    log("./profile/task_struct", "comm", Comm_addr, Base_addr),
    log("./profile/task_struct", "parent", Parent_addr, Base_addr),
    log("./profile/task_struct", "group_leader", Group_leader_addr, Base_addr),
    log("./profile/task_struct", "cred", Cred_addr, Base_addr),
    log("./profile/task_struct", "pid", Pid_addr, Base_addr),
    log("./profile/task_struct", "fs_struct", Fs_struct_addr, Base_addr),
    log("./profile/task_struct", "files", Files_addr, Base_addr),

    log("./profile/task_struct", "task_struct time", End, Start),

    print_nl('tasks offset', Tasks_offset),
    print_nl('tasks offset', Tasks_val),
    print_nl('mm offset', MM_offset),
    print_nl('comm offset', Comm_offset),
    print_nl('real_parent', Real_parent_offset),
    print_nl('group_leader', Group_leader_offset),
    print_nl("Finished, total time", Time_past).

query_module(Base_addr) :-
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
    long(Ulg),
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
        [Num_kp_addr, Num_kp_val],
        [RO_init_size_addr, RO_init_size_val]
    ]),
    %Ulong_profile = ([
        /* FIXME This could be a int or long */
    %    [Num_kp_addr, Num_kp_val]
    %]),
    
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    tuples_in(Int_profile, Int),
    %tuples_in(Ulong_profile, Ulg),
    /* Order Invariants */
    chain([List_addr, Name_addr, KP_addr, Num_kp_addr, Core_base_addr, Core_size_addr, 
            Core_text_size_addr, RO_size_addr, RO_init_size_addr], #<),
    RO_init_size_addr - Base_addr #< 1000,
    
    labeling([enum], [Name_addr, Name_val]),
    List_addr #= Name_addr - 16,
    labeling([enum], [List_addr, List_val]),
    Name_offset #= Name_addr - Base_addr,
    List_offset #= List_addr - Base_addr,
    query_list_head(List_val, Name_offset, List_offset),
    /* FIXME: problem, kp might be zero! */
    KP_val #> 0,
    Num_kp_addr #= KP_addr + 12,
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
    %print_nl("Finished, total time", Time_past).

query_mount_hash(Base_addr) :-
    statistics(real_time, [Start|_]),
    pointer(Ptr),
    Ptr_profile = ([
        [Mount_addr, Mount_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    Mount_addr #< Base_addr + 500,
    Mount_val #> 0,
    labeling([enum], [Mount_addr, Mount_val]),
    query_mount(Mount_val),
    statistics(real_time, [End|_]),
    log("./profile/mount_hash", "mount", Mount_addr, Base_addr),
    log("./profile/mount_hash", "mount_hash time", End, Start).

query_net_device(Base_addr) :- 
    /*
        char             name[NAMSIZ];
        struct list_head dev_list;
        unsigned char    addr_len;
        unsigned int     promiscuity;
        struct in_device *ip_ptr;
    */
    statistics(real_time, [Start|_]),
    %get_time(Current),
    pointer(Ptr),
    string_val(Str),
    int(Int),
    /* Type Invariants */
    Ptr_profile = ([
        [Dev_list_addr, Dev_list_val],
        [IP_ptr_addr, IP_ptr_val]
    ]),
    Str_profile = ([
        [Name_addr, Name_val]
    ]),
    Int_profile = ([
        [Promisc_addr, Promisc_val],
        [Addr_len_addr, Addr_len_val]
    ]),    
    
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    tuples_in(Int_profile, Int),
    /* Hard to determine offsets for addr_len and promisc */
    chain([Name_addr, Dev_list_addr, Addr_len_addr, Promisc_addr, IP_ptr_addr], #<),
    Name_addr #>= Base_addr,
    Name_offset #= Name_addr - Base_addr,
    IP_ptr_addr #< Base_addr + 1000,
    /* dev_list offset can be hardcoded since it remains the same */
    Dev_list_addr #= Base_addr + 80,
    labeling([enum], [Name_addr, Dev_list_addr, Dev_list_val]),
    /* do not have a good constrain to narrow down ip_ptr, use its rough offset
       to reduce the search space. 
     */
    IP_ptr_addr #> Base_addr + 700,
    IP_ptr_val #> 0,
    labeling([enum], [IP_ptr_addr, IP_ptr_val]),
    query_in_device(IP_ptr_val),

    %get_time(End),
    %Time_past is End - Current,
    statistics(real_time, [End|_]),

    log("./profile/net_device", "name", Name_addr, Base_addr),
    log("./profile/net_device", "ip_ptr", IP_ptr_addr, Base_addr),
    log("./profile/net_device", "dev_list", Dev_list_addr, Base_addr),
    log("./profile/net_device", "net_device time", End, Start).


query_inet_sock(Base_addr) :-
    /* As defined in source code, sk and pinet6 has to be 
       the first two members of inet_sock, which means we
       can hardcode this rule.
    */
    /*skc_family at offset 16 short contained in a unsigned number 
     First half of sock_common can be viewed as unchanged, so it's safe to use
       some hardcoded ruels to help pinpoint some offsets.  
    sk_buff_head, two non-zero pointers, one unsigned long, one integer.
    sk_protocol is a unsigned long number after sk_write_buffer, and they have the same offset. */
    %get_time(Current),
    statistics(real_time, [Start|_]),
    pointer(Ptr),
    long(Ulg),
    int(Int),
    /* Type Invariants */
    Ptr_profile = ([
        [Sk_receive_queue_addr, Sk_receive_queue_val],
        [Sk_receive_queue_prev_addr, Sk_receive_queue_prev_val],
        [Sk_send_head_addr, Sk_send_head_val],
        [Sk_write_queue_addr, Sk_write_queue_val],
        [Sk_write_queue_prev_addr, Sk_write_queue_prev_val]
    ]),
    Ulong_profile = ([
        [Skc_family_addr, Skc_family_val],
        [Sk_protocol_addr, Sk_protocol_val]
    ]),
    Int_profile = ([
        [Sk_rcvlowat_addr, Sk_rcvlowat_val],
        [Receive_lock_addr, Receive_lock_val],
        [Write_lock_addr, Write_lock_val],
        [Qlen_receive_addr, Qlen_receive_val],
        [Qlen_write_addr, Qlen_write_val]
    ]),    
    
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Ulong_profile, Ulg),
    tuples_in(Int_profile, Int),

    Sk_protocol_val #> 0,
    Skc_family_addr #= Base_addr + 16,
    Skc_family_val #> 0,
    Sk_receive_queue_val #> 0,
    Sk_receive_queue_prev_val #> 0,
    Sk_write_queue_val #> 0,
    Sk_write_queue_prev_val #> 0,
    chain([Skc_family_addr, Sk_rcvlowat_addr, Sk_receive_queue_addr, Sk_receive_queue_prev_addr, Qlen_receive_addr, Receive_lock_addr,
          Sk_send_head_addr, Sk_write_queue_addr, Sk_write_queue_prev_addr, Qlen_write_addr, Write_lock_addr,
          Sk_protocol_addr], #<),
    /* sock_common is at least 136 */
    Sk_receive_queue_addr #> Base_addr + 136,
    Sk_receive_queue_addr #=< Sk_rcvlowat_addr + 28,
    Sk_protocol_addr #= Sk_write_queue_addr + 160,
    Sk_protocol_addr #< Base_addr + 700,
    Sk_receive_queue_prev_addr #= Sk_receive_queue_addr + 8,
    Qlen_receive_addr #= Sk_receive_queue_prev_addr + 8,
    Receive_lock_addr #= Qlen_receive_addr + 4,
    Sk_write_queue_addr #= Sk_send_head_addr + 8,
    Sk_write_queue_prev_addr #= Sk_write_queue_addr + 8,
    Qlen_write_addr #= Sk_write_queue_prev_addr + 8,
    Write_lock_addr #= Qlen_write_addr + 4,

    labeling([enum], [Skc_family_addr, Sk_receive_queue_addr, Sk_write_queue_addr, Sk_protocol_addr]),

    %get_time(End),
    %Time_past is End - Current,
    statistics(real_time, [End|_]),


    log("./profile/inet_sock", "sk_receive_queue", Sk_receive_queue_addr, Base_addr),
    log("./profile/inet_sock", "Sk_write_queue", Sk_write_queue_addr, Base_addr),
    log("./profile/inet_sock", "Skc_family", Skc_family_addr, Base_addr),
    log("./profile/inet_sock", "Sk_protocol", Sk_protocol_addr, Base_addr),
    log("./profile/inet_sock", "inet_sock time", End, Start).

query_resource(Base_addr) :-
    /*
        start
        end
        *name
        *parent
        *sibling
        *child -> non-zero
    */
    /* This structure remains unchanged, thus we can have some
       hardcoded rules to help inference. */

    statistics(real_time, [Start|_]),
    pointer(Ptr),
    long(Ulg),
    int(Int),
    /* Type Invariants */
    Ptr_profile = ([
        [Name_addr, Name_val],
        [Parent_addr, Parent_val],
        [Sibling_addr, Sibling_val],
        [Child_addr, Child_val]
    ]),
    Ulong_profile = ([
        [End_addr, End_val],
        [Flags_addr, Flags_val]
    ]),
    Int_profile = ([
        [Start_addr, Start_val]
    ]),    
    
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Ulong_profile, Ulg),
    tuples_in(Int_profile, Int),

    Child_val #> 0,
    Start_addr #= Base_addr,
    chain([Start_addr, End_addr, Name_addr, Flags_addr, Parent_addr, Sibling_addr, Child_addr], #<),
    %Name_addr #= Base_addr + 16,
    Child_addr #=< Base_addr + 64,
    labeling([enum], [Start_addr, End_addr, Name_addr, Name_val]),
    query_string_pointer(Name_val),
    Name_offset #= Name_addr - Base_addr,
    labeling([enum], [Child_addr, Child_val]),
    query_name_pointer(Child_val, Name_offset),

    statistics(real_time, [End|_]),


    log("./profile/resource", "Start_addr", Start_addr, Base_addr),
    log("./profile/resource", "End_addr", End_addr, Base_addr),
    log("./profile/resource", "Name_addr", Name_addr, Base_addr),
    log("./profile/resource", "Child_addr", Child_addr, Base_addr),
    log("./profile/resource", "resource time", End, Start).

query_neigh_tables(Base_addr) :-
    statistics(real_time, [Start|_]),
    pointer(Ptr),
    Ptr_profile = ([
        [Neigh_table_addr, Neigh_table_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    Neigh_table_addr #=< Base_addr + 32,
    Neigh_table_val #> 0,
    labeling([enum], [Neigh_table_addr, Neigh_table_val]),
    query_neigh_table(Neigh_table_val),

    statistics(real_time, [End|_]),
    log("./profile/neigh_tables", "neigh_table", Neigh_table_addr, Base_addr),
    log("./profile/neigh_tables", "neigh_tables time", End, Start).

query_seq_operations(Base_addr) :-
    statistics(real_time, [Start|_]),
    /* Four successive function pointers */
    pointer(Ptr),
    Ptr_profile = ([
        [Start_addr, Start_val],
        [Stop_addr, Stop_val],
        [Next_addr, Next_val],
        [Show_addr, Show_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    chain([Start_addr, Stop_addr, Next_addr, Show_addr], #<),
    Start_addr #= Base_addr,
    Show_addr #= Base_addr + 24,
    Start_val #> 0,
    Stop_val #> 0,
    Next_val #> 0,
    Show_val #> 0,
    statistics(real_time, [End|_]),
    log("./profile/seq_operations", "seq_operations time", End, Start).


query_tcp_seq_afinfo(Base_addr) :-
    statistics(real_time, [Start|_]),

    pointer(Ptr),
    int(Int),
    Ptr_profile = ([
        [Name_addr, Name_val],
        [F_ops_addr, F_ops_val],
        [Ops_addr, Ops_val]
    ]),
    Int_profile = ([
        [Family_addr, Family_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Int_profile, Int),
    Name_addr #= Base_addr,
    Ops_addr #= Base_addr + 24,
    chain([Name_addr, Family_addr, F_ops_addr, Ops_addr], #<),
    
    labeling([enum], [Name_addr, Name_val]),
    query_string_pointer(Name_val),
    statistics(real_time, [End|_]),
    log("./profile/tcp_seq_afinfo", "tcp_seq_afinfo time", End, Start).

query_udp_seq_afinfo(Base_addr) :-
    statistics(real_time, [Start|_]),

    pointer(Ptr),
    int(Int),
    Ptr_profile = ([
        [Name_addr, Name_val],
        [Udp_table_addr, Udp_table_val],
        [F_ops_addr, F_ops_val],
        [Ops_addr, Ops_val]
    ]),
    Int_profile = ([
        [Family_addr, Family_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Int_profile, Int),
    Name_addr #= Base_addr,
    Ops_addr #= Base_addr + 32,
    chain([Name_addr, Family_addr, Udp_table_addr, F_ops_addr, Ops_addr], #<),
    
    labeling([enum], [Name_addr, Name_val]),
    query_string_pointer(Name_val),
    statistics(real_time, [End|_]),
    log("./profile/udp_seq_afinfo", "udp_seq_afinfo time", End, Start).

query_tty_driver(Base_addr) :-
    statistics(real_time, [Start|_]),

    /* tty_driver remains unchanged, some rules are hardcoded. */
    pointer(Ptr),
    int(Int),
    Ptr_profile = ([
        [Driver_name_addr, Driver_name_val],
        [Name_addr, Name_val],
        [Ttys_addr, Ttys_val],
        [Tty_drivers_addr, Tty_drivers_val]
    ]),
    Int_profile = ([
        [Magic_addr, Magic_val],
        [Kref_addr, Kref_val],
        [Name_base_addr, Name_base_val],
        [Major_addr, Major_val],
        [Minor_start_addr, Minor_start_val],
        [Num_addr, Num_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Int_profile, Int),
    Magic_addr #= Base_addr,
    Kref_addr #= Magic_addr + 4,
    Num_addr #= Name_base + 12,
    Ttys_addr #= Base_addr + 128,
    Tty_drivers_addr #= Base_addr + 168,
    chain([Magic_addr, Kref_addr, Driver_name_addr, Name_addr, Name_base_addr, Major_addr, Minor_start_addr,
            Num_addr, Ttys_addr, Tty_drivers_addr], #<),
    labeling([enum], [Driver_name_addr, Driver_name_val, Name_addr, Name_val]),
    query_string_pointer(Driver_name_val),
    query_string_pointer(Name_val),
    statistics(real_time, [End|_]),
    log("./profile/tty_driver", "tty_driver time", End, Start).

query_proc_dir_entry(Base_addr) :-
    statistics(real_time, [Start|_]),

    pointer(Ptr),
    int(Int),
    long(Ulg),
    Ptr_profile = ([
        [Proc_iops_addr, Proc_iops_val],
        [Proc_fops_addr, Proc_fops_val]
    ]),
    Int_profile = ([
        [Low_ino_addr, Low_ino_val],
        [Mode_addr, Mode_val],
        [Nlink_addr, Nlink_val],
        [Uid_addr, Uid_val],
        [Gid_addr, Gid_val]
    ]),

    tuples_in(Ptr_profile, Ptr),
    tuples_in(Int_profile, Int),
    Low_ino_addr #= Base_addr,
    Gid_addr #= Low_ino_addr + 16,
    Proc_fops_addr #= Proc_iops_addr + 8,
    Proc_fops_addr #=< Base_addr + 40,
    chain([Low_ino_addr, Mode_addr, Nlink_addr, Uid_addr, Gid_addr, Proc_iops_addr, Proc_fops_addr], #<),
    labeling([enum], [Proc_iops_addr, Proc_iops_val, Proc_fops_addr, Proc_fops_val]),
    Proc_fops_val #> 0,
    %Proc_iops_val #> 0,
    %query_inode_operations(Proc_iops_val),
    query_inode_operations(Proc_fops_val),
    statistics(real_time, [End|_]),
    log("./profile/proc_dir_entry", "proc_dir_entry time", End, Start).

query_kset(Base_addr) :-
    /* skip */
    1 #= 1.



test(Base_addr) :-
    get_time(Current),
    current_predicate(string_val/1),
    pointer(Ptr),
    string_val(Str),
    int(Int),
    Ptr_profile = ([
        [MM2_addr, MM2_val],
        [Tasks_addr, Tasks_val],
        [Parent_addr, Parent_val],
        [Real_parent_addr, Real_parent_val],
        [Child_addr, Child_val],
        [Group_leader_addr, Group_leader_val],
        [Thread_group_addr, Thread_group_val],
        [Cred_addr, Cred_val],
        [FS_struct_addr, FS_struct_val]
    ]),
    Str_profile = ([
        [Comm_addr, Comm_val]    
    ]),
    Int_profile = ([
        [Pid_addr, Pid_val],
        [Tgid_addr, Tgid_val]    
    ]),
    chain([Tasks_addr, MM2_addr, Pid_addr, Tgid_addr, Parent_addr, Real_parent_addr, Child_addr, 
           Group_leader_addr, Thread_group_addr, Cred_addr, Comm_addr, FS_struct_addr], #<),
    MM2_addr #> Base_addr + 1000,
    Tasks_addr #> MM2_addr - 100,
    FS_struct_addr #< Base_addr + 3000,
    Tgid_addr #= Pid_addr + 4,
    Parent_addr #< Tgid_addr + 20,
    Real_parent_addr #= Parent_addr + 8,
    Child_addr #= Real_parent_addr +8,
    Group_leader_addr #=< Child_addr +32,
    %Comm_addr #= Base_addr + 2584,
    %Tasks_addr #= Base_addr + 1904,
    %FS_struct_addr #= Base_addr + 2640,


    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    tuples_in(Int_profile, Int),

    label([MM2_addr, MM2_val]),
    % make query after labeling
    MM2_val #> 0,
    query_mm_struct(MM2_val),
    labeling([enum], [Tasks_addr, Tasks_val,  Comm_addr, Comm_val ]),
    %Tasks_addr #= Base_addr + 2040,
    Comm_offset #= Comm_addr - Base_addr,
    Tasks_offset #= Tasks_addr - Base_addr,
    Tasks_val #> 0,
    query_list_head(Tasks_val, Comm_offset, Tasks_offset),

    


    get_time(End),
    Time_past is End - Current,
    MM_offset #= MM2_addr - Base_addr,
    Real_parent_offset #= Real_parent_addr - Base_addr,
    Group_leader_offset #= Group_leader_addr - Base_addr,
    
    print_nl('tasks offset', Tasks_offset),
    print_nl('mm offset', MM_offset),
    print_nl('comm offset', Comm_offset),
    print_nl('real_parent', Real_parent_offset),
    print_nl('group_leader', Group_leader_offset),
    print_nl("Finished, total time", Time_past).

query_neigh_table(Base_addr) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "neigh_table"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_string_pointer(Val) :- 
    process_create(path('python'),
                    ['subquery.py', Val, "string_pointer"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_name_pointer(Val, Name_offset) :-
    process_create(path('python'),
                    ['subquery.py', Val, "name_pointer", Name_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_mount(Base_addr) :- 
    process_create(path('python'),
                    ['subquery.py', Base_addr, "mount"],
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

query_vfs_mount(Vfsmount_val) :-
    process_create(path('python'),
                    ['subquery.py', Vfsmount_val, "vfs_mount"],
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

query_kernel_param(KP_val) :-
    process_create(path('python'),
                    ['subquery.py', KP_val, "kernel_param"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_in_device(IP_ptr_val) :-
    process_create(path('python'),
                    ['subquery.py', IP_ptr_val, "in_device"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_inode_operations(Base_addr) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "inode_operations"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_mm_struct(MM2_val) :-
    process_create(path('python'),
                    ['subquery.py', MM2_val, "mm_struct"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_mm_struct_arm(MM2_val) :-
    process_create(path('python'),
                    ['subquery.py', MM2_val, "mm_struct_arm"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_list_head(Tasks_val, Comm_offset, Tasks_offset) :-
    process_create(path('python'),
                    ['subquery.py', Tasks_val, "list_head", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_tasks(Tasks_val, Comm_offset, Tasks_offset) :-
    process_create(path('python'),
                    ['subquery.py', Tasks_val, "tasks", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_child(Child_val, Comm_offset, Child_offset) :-
    process_create(path('python'),
                    ['subquery.py', Child_val, "child", Comm_offset, Child_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_ts(Base_addr, Comm_offset, Tasks_offset) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "ts", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_cred(Base_addr) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "cred"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).
query_fs_struct(Base_addr) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "fs_struct"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

print_nl(Name, Content):- 
    print(Name),
    print(':'),
    print(Content),
    nl.

