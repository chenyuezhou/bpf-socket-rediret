# bpf-socket-rediret

Enabling applications to transparently bypass the TCP/IP stack using eBPF when those applications are on the same host.

# bpftool

```
make -C /lib/modules/`uname -r`/source/tools/ bpf_install
```

bpftool is located in ```/lib/modules/`uname -r`/source/tools/bpf/bpftool/```

# build

```
make
```

# run

load bpf program. (bpf-sockops,bpf-redir)

```
bpftool prog load src/bpf-sockops /sys/fs/bpf/bpf-sockops type sockops pinmaps /sys/fs/bpf
bpftool prog load src/bpf-redir /sys/fs/bpf/bpf-redir type sk_msg map name sock_ops_map pinned /sys/fs/bpf/sock_ops_map
```

mount cgroup. (cgroup2 is required)

```
mount -t cgroup2 test /root/cgroup
```

attach bpf program.

```
bpftool cgroup attach /root/cgroup sock_ops pinned /sys/fs/bpf/bpf-sockops
bpftool prog attach pinned /sys/fs/bpf/bpf-redir msg_verdict pinned /sys/fs/bpf/sock_ops_map
```

# remove

detach bpf program.

```
bpftool prog detach pinned /sys/fs/bpf/bpf-redir msg_verdict pinned /sys/fs/bpf/sock_ops_map
bpftool cgroup detach /root/cgroup sock_ops pinned /sys/fs/bpf/bpf-sockops
```

offload bpf program and bpf map.

```
unlink /sys/fs/bpf/bpf-redir
unlink /sys/fs/bpf/bpf-sockops
unlink /sys/fs/bpf/sock_ops_map
```
