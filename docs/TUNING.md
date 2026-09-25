# Host tuning

Recommended sysctls for every server and gateway host. Without the raised `rmem_max`/`wmem_max` ceiling a single tunnel is capped at a few tens of Mbit/s on high-RTT paths.

Every host runs:

`/etc/sysctl.d/99-bbr.conf`:
```
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
```

`/etc/sysctl.d/99-tcptune.conf`:
```
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 131072 33554432
net.ipv4.tcp_wmem = 4096 131072 33554432
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
```

`/etc/modules-load.d/bbr.conf`:
```
tcp_bbr
```

