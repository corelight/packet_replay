### Python-based PCAP replay

Try to replay packets.

With `vxlan`, tries to encapsulate packets from the given pcap file/directory in a VXLAN header and send to specified target.

With `geneve`, same as above but GENEVE encapsulated

With `packet`, tries to send packets from the given pcap file/directory out the specified interface.

`replay.py ... vxlan` and `replay.py ... geneve` do not require root privileges, `replay.py ... packet` does.

Depends on scapy (`apt install python3-scapy`)

Examples:

```
# replay packets.pcap, vxlan encapsulated, and send to 172.17.0.13
./replay.py packets.pcap vxlan -t 172.17.0.13

# replay packets.pcap, send raw packets on eth1 (needs root)
./replay.py packets.pcap packet -i eth1

# replay all pcaps under packet_dir in around 1 hour (3600 seconds)
# vlan encapsulate and send to 172.17.0.13
./sched_replay.py -d 3600 packet_dir/ vxlan -t 172.17.0.13

# replay packets.pcap, at 100x the original rate, geneve-encapsulated to
# 172.17.0.13, and include a non-standard geneve option containing the filename
./replay.py -s 100 packets.pcap geneve -T -t 172.17.0.13
```
