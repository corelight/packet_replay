### Python-based PCAP replay (alpha)

Try to replay packets.  Currently, tries to encapsulate packets from the given pcap file in a VXLAN header and send to specified target.

The `replay_vxlan.py` script does not require root privileges.

Depends on scapy (`apt install python3-scapy`)

Example:

```
replay_vxlan.py -t 172.17.0.40 packets.pcap
```
