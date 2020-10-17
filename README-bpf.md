
# bpf

On the Google Console, check "allow http traffic" for this VM.

Install necessary dependencies:

```
$ sudo apt update
$ sudo apt install make llvm clang golang-go
$ git clone git@github.com:cilium/cilium.git
$ git clone git@github.com:b3a-dev/ebpf-geoip-demo.git
$ cd bpf-geoip-demo
```

Compile and install the eBPF program:
```
$ CILIUM_DIR=~/cilium/ make -C bpf/
$ sudo tc qdisc add dev ens4 clsact
$ sudo tc filter add dev ens4 ingress bpf da obj bpf/tc-prog.o sec bpf-prog
$ sudo tc filter show dev ens4 ingress
$ sudo tc filter protocol all pref 49152 bpf chain 0
$ sudo tc filter protocol all pref 49152 bpf chain 0 handle 0x1 tc-prog.o:[bpf-prog] direct-action not_in_hw id 77 tag 1e2a2ca8a73223a5 jited
```

Compile go program and inspect incoming TCP packets with a destination port 80
```
$ cd read-perf
$ go build
$ sudo ./read-perf
```

Access http://XXXXXXXX on your browser where XXXXXXXX is the public IP of your
google VM. The site will not work, but you should your IP on the output of
`read-perf`.

## Cleanup

```
$ sudo sudo tc filter delete dev ens4 ingress pref 49152 handle 0x1 bpf 
$ sudo rm /sys/fs/bpf/tc/globals/xevents
```
