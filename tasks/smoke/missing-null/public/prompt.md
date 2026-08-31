# Repair the eBPF program

The XDP program in `broken.c` must increment element zero of the `packet_count` array map
for every packet and return `XDP_PASS`.

Return one complete C translation unit. Preserve the map update and observable behavior.
The evaluator fixes the compiler command, program type, section, and loader environment.
