
/*
 * Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com)
 */


#include <bpf_sockops.h>


SEC("sk_msg")
int bpf_redir(struct sk_msg_md *msg) {
    struct sock_key skk = {};
    int             ret;

    if (msg->family != AF_INET) {
        return SK_PASS;
    }

    if (msg->remote_ip4 != msg->local_ip4) {
        return SK_PASS;
    }

    skk.remote_ip4 = msg->remote_ip4;
    skk.local_ip4  = msg->local_ip4;

    skk.remote_port = msg->local_port;
    skk.local_port  = bpf_ntohl(msg->remote_port);

    skk.family = msg->family;

    ret = bpf_msg_redirect_hash(msg, &sock_ops_map, &skk, BPF_F_INGRESS);

#ifdef DEBUG
    bpf_printk("redirect  port %d --> %d\n", msg->local_port,
            bpf_ntohl(msg->remote_port));
    if (ret != SK_PASS) {
        /* key not in map */
        bpf_printk("bpf_msg_redirect_hash() failed\n");
    }
#endif

    return SK_PASS;
}


char _license[] SEC("license") = "GPL";
