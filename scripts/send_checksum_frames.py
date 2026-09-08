"""Send frames whose IP and/or UDP checksums are deliberately correct or corrupt.

    send_checksum_frames.py <netdev> <dst-mac> good|bad-ip|bad-l4|bad-both <count>

One corruption at a time, on purpose. A NIC that stamps GOOD unconditionally is
indistinguishable from a working offload unless you can compare the modes -- and
isolating IP from L4 is what showed that mlx5 reports the two independently.

Companion to dpdk/examples/checksum_offload_probe.rs. Send *after* the probe is
polling: EAL start-up in a container takes ~10s, and frames sent before then are
simply lost.
"""
import socket, struct, sys

dev, dst_mac, mode, count = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
dst = bytes.fromhex(dst_mac.replace(":", ""))
src = bytes.fromhex("020000000002")

def csum(b):
    if len(b) % 2:
        b += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def frame(i, bad_ip, bad_l4):
    payload = bytes(((i + j) & 0xFF) for j in range(64))
    saddr = struct.pack("!BBBB", 10, 0, (i >> 8) & 0xFF, i & 0xFF)
    daddr = struct.pack("!BBBB", 10, 1, 0, 1)
    sport, dport = 4000 + (i % 1000), 4789
    # UDP with a real checksum over the pseudo-header + payload.
    udp_len = 8 + len(payload)
    pseudo = saddr + daddr + struct.pack("!BBH", 0, 17, udp_len)
    udp_nocsum = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload
    ucs = csum(pseudo + udp_nocsum) or 0xFFFF
    if bad_l4:
        ucs ^= 0xBEEF          # deliberately wrong L4 checksum
    udp = struct.pack("!HHHH", sport, dport, udp_len, ucs) + payload

    total = 20 + udp_len
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, i & 0xFFFF, 0, 64, 17, 0) + saddr + daddr
    ics = csum(hdr)
    if bad_ip:
        ics ^= 0x1234          # deliberately wrong IP checksum
    hdr = hdr[:10] + struct.pack("!H", ics) + hdr[12:]
    return dst + src + b"\x08\x00" + hdr + udp

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((dev, 0))
bad_ip = mode in ("bad-ip", "bad-both")
bad_l4 = mode in ("bad-l4", "bad-both")
for i in range(count):
    s.send(frame(i, bad_ip, bad_l4))
print(f"sent {count} frames on {dev} to {dst_mac} (mode={mode}: bad_ip={bad_ip} bad_l4={bad_l4})")
