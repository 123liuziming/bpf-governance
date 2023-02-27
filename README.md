# bpf-governance
Service governance based on ebpf. Including traffic control, label routing and etc...

## Flow Control
Mount the EBPF program to the Linux tc hook to record the statistic data and also pass/drop the specific packet.
