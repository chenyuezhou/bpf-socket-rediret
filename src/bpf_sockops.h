
/*
 * Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com)
 */


#ifndef BPF_SOCKOPS_H
#define BPF_SOCKOPS_H


#include <sys/socket.h>
#include <linux/bpf.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>

#include <compiler.h>


#ifndef MAX_SOCK_OPS_MAP_ENTRIES
#define MAX_SOCK_OPS_MAP_ENTRIES 65535
#endif


struct sock_key {
    __u32 remote_ip4;
    __u32 local_ip4;

    __u32 remote_port;
    __u32 local_port;

    __u32 family;
};


struct bpf_map_def SEC("maps") sock_ops_map = {
    .type        = BPF_MAP_TYPE_SOCKHASH,
    .key_size    = sizeof(struct sock_key),
    .value_size  = sizeof(int),
    .max_entries = MAX_SOCK_OPS_MAP_ENTRIES,
};


#endif /* BPF_SOCKOPS_H */
