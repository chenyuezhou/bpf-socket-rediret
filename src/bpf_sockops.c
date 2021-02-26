
/*
 * Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com)
 */


#include <bpf_sockops.h>


static __always_inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops) {
    struct sock_key skk = {};
    int             ret;

    skk.remote_ip4 = skops->remote_ip4;
    skk.local_ip4  = skops->local_ip4;

    skk.local_port  = skops->local_port; /* host byte order */
    skk.remote_port = bpf_ntohl(skops->remote_port); /* network byte order */

    skk.family = skops->family;

    /* bpf use offset to translate bpf_sock_ops to bpf_sock_ops_kern */
    ret = bpf_sock_hash_update(skops, &sock_ops_map, &skk, BPF_NOEXIST);
    if (ret) {
        /* update failed */
        bpf_printk("bpf_sock_hash_update() failed. %d\n", -ret);

        return;
    }

#ifdef DEBUG
    bpf_printk("Sockmap op: %d, port %d --> %d\n", skops->op,
            skk.local_port, skk.remote_port);
#endif
}


SEC("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops) {
    __u32           op;

    op = skops->op;

    if (skops->family != AF_INET) {
        /* support IPV4 only yet */
        return 0;
    }

    if (skops->remote_ip4 != skops->local_ip4) {
        return 0;
    }

    switch (op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            bpf_sock_ops_ipv4(skops);

            break;

        default:
            break;
    }

    return 0;
}


char _license[] SEC("license") = "GPL";
