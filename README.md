# Packet Storm

### Objectives

1. Calculate the average packet size and the total volume of data received during the attack.
2. Calculate the destination IPs ranked by frequency.
3. Calculate the number of packets sent with different transport layer protocols.

### Building

The build system is CMake. To build the executable:

```bash
cmake -B build
cmake --build build
```

### Running

The program assumes a pcap file named `packet-storm.pcap` exists in the location where the program is executed from.

To run the executable:

`./build/pstorm`

### Output

High-level information will be output to the terminal.

More detailed analyis is output to `dst_ip_analysis.txt` and `proto_analysis.txt`.

The `dst_ip_analysis.txt` file will show all observed destination IPs ranked by the number of times they were seen.

The `proto_analysis.txt` file will show all observed transport layer protocols with the number of packets associated with each protocol. The protocol identifier can be looked up in `netinet/in.h` under the definitions prefixed `IPPROTO_`.

Example output files have been included in the repo.

### Notes

- The external library `libpcap` is used for packet analysis.

### Caveats

Apart from compiling for speed, no other code optimisations have been considered.

```bash
[17:10:10] andy:packet-storm git:(main*) $ time ./build/pstorm
Average packet size: 147 B
Total volume of data: 93968864 B
./build/pstorm  0.37s user 0.03s system 99% cpu 0.408 total
```

### Results

- **Average packet size:** 147 B.
- **Total volume of data:** 93968864 B (93.97 MB).
- **Most seen destination IP:** 229.154.57.192 (17) -- (Further analysis available in `dst_ip_analysis.txt.example`).
- **Transport protocol breakdown:** UDP (59163), TCP (940837).
