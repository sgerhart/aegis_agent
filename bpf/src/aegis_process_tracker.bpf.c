// eBPF program for process monitoring and tracking
// This program tracks processes and their network connections

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/limits.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Process tracking map
struct process_info {
    __u32 pid;
    __u32 ppid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char exe_path[PATH_MAX];
    __u64 start_time;
    __u64 last_seen;
    __u32 namespace_id;
    __u32 mount_namespace;
    __u32 net_namespace;
    __u32 pid_namespace;
    __u32 user_namespace;
    __u32 uts_namespace;
    __u32 ipc_namespace;
    __u32 cgroup_namespace;
    __u32 capabilities;
    __u32 session_id;
    __u32 flags;
    __u8 padding[4];
};

// Process to network connection mapping
struct process_network_conn {
    __u32 process_id;
    __u32 socket_fd;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 state;
    __u64 bytes_sent;
    __u64 bytes_recv;
    __u64 packets_sent;
    __u64 packets_recv;
    __u64 start_time;
    __u64 last_activity;
    __u32 socket_type;
    __u32 socket_family;
    char process_name[TASK_COMM_LEN];
    __u8 padding[3];
};

// File access tracking
struct process_file_access {
    __u32 process_id;
    __u32 file_fd;
    __u32 file_inode;
    __u32 file_dev;
    __u32 access_mode; // O_RDONLY, O_WRONLY, O_RDWR, etc.
    __u32 open_flags;
    char file_path[PATH_MAX];
    char process_name[TASK_COMM_LEN];
    __u64 timestamp;
    __u64 file_size;
    __u32 file_mode;
    __u32 file_uid;
    __u32 file_gid;
    __u8 padding[4];
};

// System call tracking
struct process_syscall {
    __u32 process_id;
    __u32 syscall_nr;
    __u64 syscall_args[6];
    __u64 return_value;
    __u64 timestamp;
    char process_name[TASK_COMM_LEN];
    __u32 uid;
    __u32 gid;
    __u32 namespace_id;
    __u8 success; // 0=failed, 1=success
    __u8 padding[3];
};

// Process execution tracking
struct process_execution {
    __u32 process_id;
    __u32 parent_pid;
    char executable_path[PATH_MAX];
    char command_line[512];
    char process_name[TASK_COMM_LEN];
    __u64 start_time;
    __u64 end_time;
    __u32 uid;
    __u32 gid;
    __u32 namespace_id;
    __u32 exit_code;
    __u8 success; // 0=failed, 1=success
    __u8 padding[3];
};

// Maps for process tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32); // PID
    __type(value, struct process_info);
} process_tracking_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 50000);
    __type(key, __u64); // process_id << 32 | socket_fd
    __type(value, struct process_network_conn);
} process_network_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 30000);
    __type(key, __u64); // process_id << 32 | file_fd
    __type(value, struct process_file_access);
} process_file_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} process_syscall_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} process_exec_ringbuf SEC(".maps");

// Per-CPU arrays for temporary storage
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct process_info);
} temp_process_info SEC(".maps");

// Helper function to get current timestamp
static __always_inline __u64 get_timestamp() {
    return bpf_ktime_get_ns();
}

// Helper function to get process information
static __always_inline int get_process_info(__u32 pid, struct process_info *info) {
    struct task_struct *task;
    struct task_struct *parent;
    
    // Get task struct for the process
    task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return -1;
    
    // Fill process information
    info->pid = pid;
    info->ppid = BPF_CORE_READ(task, real_parent, tgid);
    info->tgid = BPF_CORE_READ(task, tgid);
    info->uid = BPF_CORE_READ(task, cred, uid.val);
    info->gid = BPF_CORE_READ(task, cred, gid.val);
    
    // Get process name
    bpf_get_current_comm(&info->comm, sizeof(info->comm));
    
    // Get start time
    info->start_time = BPF_CORE_READ(task, start_time);
    info->last_seen = get_timestamp();
    
    // Get namespace information
    info->namespace_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    info->mount_namespace = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    info->net_namespace = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    info->pid_namespace = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    info->user_namespace = BPF_CORE_READ(task, nsproxy, user_ns, ns.inum);
    info->uts_namespace = BPF_CORE_READ(task, nsproxy, uts_ns, ns.inum);
    info->ipc_namespace = BPF_CORE_READ(task, nsproxy, ipc_ns, ns.inum);
    info->cgroup_namespace = BPF_CORE_READ(task, nsproxy, cgroup_ns, ns.inum);
    
    // Get capabilities
    info->capabilities = BPF_CORE_READ(task, cred, cap_effective.val);
    
    // Get session ID
    info->session_id = BPF_CORE_READ(task, sessionid);
    
    return 0;
}

// Trace point for process execution
SEC("tp/sched/sched_process_exec")
int trace_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct process_execution *exec_info;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Allocate space in ring buffer
    exec_info = bpf_ringbuf_reserve(&process_exec_ringbuf, sizeof(*exec_info), 0);
    if (!exec_info)
        return 0;
    
    // Fill execution information
    exec_info->process_id = pid;
    exec_info->start_time = get_timestamp();
    exec_info->uid = bpf_get_current_uid_gid();
    exec_info->gid = bpf_get_current_uid_gid() >> 32;
    exec_info->success = 1;
    
    // Get process name
    bpf_get_current_comm(&exec_info->process_name, sizeof(exec_info->process_name));
    
    // Get executable path (simplified)
    bpf_probe_read_str(exec_info->executable_path, sizeof(exec_info->executable_path), 
                       (void *)BPF_CORE_READ(ctx, filename));
    
    // Get command line (simplified)
    bpf_probe_read_str(exec_info->command_line, sizeof(exec_info->command_line), 
                       (void *)BPF_CORE_READ(ctx, filename));
    
    // Submit to ring buffer
    bpf_ringbuf_submit(exec_info, 0);
    
    // Update process tracking map
    struct process_info *info = bpf_map_lookup_elem(&process_tracking_map, &pid);
    if (!info) {
        struct process_info new_info = {};
        if (get_process_info(pid, &new_info) == 0) {
            bpf_map_update_elem(&process_tracking_map, &pid, &new_info, BPF_ANY);
        }
    } else {
        info->last_seen = get_timestamp();
        bpf_map_update_elem(&process_tracking_map, &pid, info, BPF_ANY);
    }
    
    return 0;
}

// Trace point for process exit
SEC("tp/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    struct process_execution *exec_info;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Allocate space in ring buffer
    exec_info = bpf_ringbuf_reserve(&process_exec_ringbuf, sizeof(*exec_info), 0);
    if (!exec_info)
        return 0;
    
    // Fill exit information
    exec_info->process_id = pid;
    exec_info->end_time = get_timestamp();
    exec_info->exit_code = BPF_CORE_READ(ctx, code);
    exec_info->success = (exec_info->exit_code == 0) ? 1 : 0;
    
    // Get process name
    bpf_get_current_comm(&exec_info->process_name, sizeof(exec_info->process_name));
    
    // Submit to ring buffer
    bpf_ringbuf_submit(exec_info, 0);
    
    // Remove from process tracking map
    bpf_map_delete_elem(&process_tracking_map, &pid);
    
    return 0;
}

// Trace point for socket creation
SEC("tp/syscalls/sys_enter_socket")
int trace_socket_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 domain = (__u32)ctx->args[0];
    __u32 type = (__u32)ctx->args[1];
    __u32 protocol = (__u32)ctx->args[2];
    
    // Store socket creation info for later use
    struct process_network_conn conn = {};
    conn.process_id = pid;
    conn.socket_family = domain;
    conn.socket_type = type;
    conn.protocol = (__u8)protocol;
    conn.start_time = get_timestamp();
    
    // Get process name
    bpf_get_current_comm(&conn.process_name, sizeof(conn.process_name));
    
    // Store in temp map for later completion
    __u32 temp_key = pid;
    bpf_map_update_elem(&temp_process_info, &temp_key, &conn, BPF_ANY);
    
    return 0;
}

// Trace point for socket creation completion
SEC("tp/syscalls/sys_exit_socket")
int trace_socket_exit(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __s64 fd = ctx->ret;
    
    if (fd < 0)
        return 0; // Socket creation failed
    
    // Get stored socket info
    struct process_network_conn *temp_conn = bpf_map_lookup_elem(&temp_process_info, &pid);
    if (!temp_conn)
        return 0;
    
    // Complete connection info
    temp_conn->socket_fd = (__u32)fd;
    temp_conn->state = 0; // Unknown state initially
    
    // Store in process network map
    __u64 key = ((__u64)pid << 32) | (__u64)fd;
    bpf_map_update_elem(&process_network_map, &key, temp_conn, BPF_ANY);
    
    // Clean up temp map
    bpf_map_delete_elem(&temp_process_info, &pid);
    
    return 0;
}

// Trace point for connect system call
SEC("tp/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __s32 fd = (__s32)ctx->args[0];
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    
    if (fd < 0)
        return 0;
    
    // Look up connection in process network map
    __u64 key = ((__u64)pid << 32) | (__u64)fd;
    struct process_network_conn *conn = bpf_map_lookup_elem(&process_network_map, &key);
    if (!conn)
        return 0;
    
    // Parse address based on family
    if (addr) {
        __u16 family = BPF_CORE_READ(addr, sa_family);
        if (family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)addr;
            conn->dst_ip = BPF_CORE_READ(sin, sin_addr.s_addr);
            conn->dst_port = BPF_CORE_READ(sin, sin_port);
        } else if (family == AF_INET6) {
            // Handle IPv6 (simplified)
            conn->dst_ip = 0; // Placeholder
            conn->dst_port = 0;
        }
    }
    
    // Update connection state
    conn->state = 1; // Connecting
    conn->last_activity = get_timestamp();
    
    // Update map
    bpf_map_update_elem(&process_network_map, &key, conn, BPF_ANY);
    
    return 0;
}

// Trace point for file open
SEC("tp/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __s32 dirfd = (__s32)ctx->args[0];
    char *pathname = (char *)ctx->args[1];
    __u32 flags = (__u32)ctx->args[2];
    __u32 mode = (__u32)ctx->args[3];
    
    // Store file access info for later use
    struct process_file_access file_access = {};
    file_access.process_id = pid;
    file_access.access_mode = flags & O_ACCMODE;
    file_access.open_flags = flags;
    file_access.timestamp = get_timestamp();
    
    // Get process name
    bpf_get_current_comm(&file_access.process_name, sizeof(file_access.process_name));
    
    // Get file path (simplified)
    bpf_probe_read_str(file_access.file_path, sizeof(file_access.file_path), pathname);
    
    // Store in temp map
    __u32 temp_key = pid;
    bpf_map_update_elem(&temp_process_info, &temp_key, &file_access, BPF_ANY);
    
    return 0;
}

// Trace point for file open completion
SEC("tp/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __s64 fd = ctx->ret;
    
    if (fd < 0)
        return 0; // File open failed
    
    // Get stored file access info
    struct process_file_access *file_access = bpf_map_lookup_elem(&temp_process_info, &pid);
    if (!file_access)
        return 0;
    
    // Complete file access info
    file_access->file_fd = (__u32)fd;
    
    // Store in process file map
    __u64 key = ((__u64)pid << 32) | (__u64)fd;
    bpf_map_update_elem(&process_file_map, &key, file_access, BPF_ANY);
    
    // Clean up temp map
    bpf_map_delete_elem(&temp_process_info, &pid);
    
    return 0;
}

// Trace point for system calls (general)
SEC("tp/syscalls/sys_enter")
int trace_syscall_enter(struct trace_event_raw_sys_enter *ctx) {
    struct process_syscall *syscall_info;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 syscall_nr = ctx->id;
    
    // Only track specific system calls to avoid overhead
    if (syscall_nr != __NR_socket && syscall_nr != __NR_connect && 
        syscall_nr != __NR_openat && syscall_nr != __NR_execve &&
        syscall_nr != __NR_fork && syscall_nr != __NR_clone)
        return 0;
    
    // Allocate space in ring buffer
    syscall_info = bpf_ringbuf_reserve(&process_syscall_ringbuf, sizeof(*syscall_info), 0);
    if (!syscall_info)
        return 0;
    
    // Fill system call information
    syscall_info->process_id = pid;
    syscall_info->syscall_nr = syscall_nr;
    syscall_info->timestamp = get_timestamp();
    syscall_info->uid = bpf_get_current_uid_gid();
    syscall_info->gid = bpf_get_current_uid_gid() >> 32;
    
    // Get process name
    bpf_get_current_comm(&syscall_info->process_name, sizeof(syscall_info->process_name));
    
    // Store system call arguments
    for (int i = 0; i < 6; i++) {
        syscall_info->syscall_args[i] = ctx->args[i];
    }
    
    // Submit to ring buffer
    bpf_ringbuf_submit(syscall_info, 0);
    
    return 0;
}

// Trace point for system call completion
SEC("tp/syscalls/sys_exit")
int trace_syscall_exit(struct trace_event_raw_sys_exit *ctx) {
    struct process_syscall *syscall_info;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 syscall_nr = ctx->id;
    __s64 ret = ctx->ret;
    
    // Only track specific system calls
    if (syscall_nr != __NR_socket && syscall_nr != __NR_connect && 
        syscall_nr != __NR_openat && syscall_nr != __NR_execve &&
        syscall_nr != __NR_fork && syscall_nr != __NR_clone)
        return 0;
    
    // Allocate space in ring buffer
    syscall_info = bpf_ringbuf_reserve(&process_syscall_ringbuf, sizeof(*syscall_info), 0);
    if (!syscall_info)
        return 0;
    
    // Fill system call information
    syscall_info->process_id = pid;
    syscall_info->syscall_nr = syscall_nr;
    syscall_info->return_value = ret;
    syscall_info->timestamp = get_timestamp();
    syscall_info->success = (ret >= 0) ? 1 : 0;
    syscall_info->uid = bpf_get_current_uid_gid();
    syscall_info->gid = bpf_get_current_uid_gid() >> 32;
    
    // Get process name
    bpf_get_current_comm(&syscall_info->process_name, sizeof(syscall_info->process_name));
    
    // Submit to ring buffer
    bpf_ringbuf_submit(syscall_info, 0);
    
    return 0;
}

char _license[] SEC("license") = "GPL";
