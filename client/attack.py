import socket
import struct
import time
import os
import select

ICMP_TIMESTAMP_REQUEST = 13
ICMP_TIMESTAMP_REPLY = 14
SERVER_IP = "172.20.0.2"

def checksum(data):
    """Calculate ICMP checksum"""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def ms_since_midnight():
    """Get milliseconds since midnight UTC"""
    now = time.time()
    seconds_since_midnight = now - (now // 86400) * 86400
    return int(seconds_since_midnight * 1000)

def create_icmp_timestamp_request(id, seq):
    """Create ICMP timestamp request packet"""
    type = ICMP_TIMESTAMP_REQUEST
    code = 0
    chksum = 0
    originate = ms_since_midnight()
    receive = 0
    transmit = 0
    
    header = struct.pack('!BBHHH', type, code, chksum, id, seq)
    data = struct.pack('!III', originate, receive, transmit)
    chksum = checksum(header + data)
    header = struct.pack('!BBHHH', type, code, chksum, id, seq)
    return header + data

def parse_icmp_timestamp_reply(packet):
    """Parse ICMP timestamp reply"""
    type, code, chksum, id, seq = struct.unpack('!BBHHH', packet[:8])
    if type != ICMP_TIMESTAMP_REPLY:
        return None
    originate, receive, transmit = struct.unpack('!III', packet[8:20])
    return originate, receive, transmit

def timestamp_to_time(ms):
    """Convert ms since midnight to HH:MM:SS.mmm"""
    hours = (ms // (1000 * 3600)) % 24
    minutes = (ms // (1000 * 60)) % 60
    seconds = (ms // 1000) % 60
    millis = ms % 1000
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}.{millis:03d}"

def client_mode():
    """Send ICMP timestamp request and receive reply"""
    print("Sending ICMP Timestamp Request to server")
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    
    # Send request
    id = os.getpid() & 0xffff
    seq = 1
    request_packet = create_icmp_timestamp_request(id, seq)
    sock.sendto(request_packet, (SERVER_IP, 0))
    
    # Wait for reply
    while True:
        ready = select.select([sock], [], [], 5.0)  # Timeout 5s
        if not ready[0]:
            print("No response received (timeout)")
            break
        packet, addr = sock.recvfrom(65535)
        if addr[0] != SERVER_IP:
            continue
        
        # Skip IP header (20 bytes)
        icmp_packet = packet[20:]
        timestamps = parse_icmp_timestamp_reply(icmp_packet)
        if timestamps:
            originate, receive, transmit = timestamps
            print("Received ICMP Timestamp Reply from server:")
            print(f"  Originate: {timestamp_to_time(originate)} (client send time)")
            print(f"  Receive:   {timestamp_to_time(receive)} (server receive time)")
            print(f"  Transmit:  {timestamp_to_time(transmit)} (server transmit time)")
            break

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root (for raw sockets).")
        exit(1)
    client_mode()