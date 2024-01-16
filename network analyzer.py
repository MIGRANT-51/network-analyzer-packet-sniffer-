import socket
import struct
import textwrap
import binascii
import sys

# Define constants for indentation
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


def main():
    """
    Main function for packet analysis.
    """
    try:
        # Create a raw socket to capture packets
        conn = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except socket.error as e:
        print(f"Socket creation error: {e}")
        sys.exit(1)

    # Define filters for ICMP, UDP, and TCP
    filters = [["ICMP", 1, "ICMPv6"], ["UDP", 17, "UDP"], ["TCP", 6, "TCP"]]
    filter = []

    # Check if a filter argument is provided via command line
    if len(sys.argv) == 2:
        print("This is the filter: ", sys.argv[1])
        # Set the filter based on the command line argument
        for f in filters:
            if sys.argv[1] == f[0]:
                filter = f

    while True:
        try:
            # Receive raw data and source address
            raw_data, addr = conn.recvfrom(65536)
        except socket.error as e:
            print(f"Error receiving data: {e}")
            continue

        # Extract destination MAC, source MAC, protocol type, and packet data
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        # Check the protocol type and proceed accordingly
        if eth_proto == 'IPV6':
            new_packet, next_proto = ipv6_header(data, filter)
            print_packets_v6(filter, next_proto, new_packet)

        elif eth_proto == 'IPV4':
            print_packets_v4(filter, data, raw_data)


def print_packets_v4(filter, data, raw_data):
    """
    Print details of IPv4 packets based on the specified filter.
    """
    version, header_length, ttl, proto, src, target, data = ipv4_packet(data)

    # ICMP
    if proto == 1 and (not filter or filter[1] == 1):
        icmp_type, code, checksum, data = icmp_packet(data)
        print("*******************ICMP***********************")
        print("\tICMP type: %s" % icmp_type)
        print("\tICMP code: %s" % code)
        print("\tICMP checksum: %s" % checksum)

    # TCP
    elif proto == 6 and (not filter or filter[1] == 6):
        print_tcp_packets_v4(version, header_length, ttl, proto, src, target, raw_data)

    # UDP
    elif proto == 17 and (not filter or filter[1] == 17):
        print_udp_packets_v4(version, header_length, ttl, proto, src, target, data)


def print_tcp_packets_v4(version, header_length, ttl, proto, src, target, raw_data):
    """
    Print details of TCP packets based on IPv4.
    """
    print("*******************TCPv4***********************")
    print('Version: {}\nHeader Length: {}\nTTL: {}'.format(version, header_length, ttl))
    print('protocol: {}\nSource: {}\nTarget: {}'.format(proto, src, target))
    src_port, dest_port, sequence, acknowledgment, flags = struct.unpack('! H H L L H', raw_data[:14])

    print('*****TCP Segment*****')
    print('Source Port: {}\nDestination Port: {}'.format(src_port, dest_port))
    print('Sequence: {}\nAcknowledgment: {}'.format(sequence, acknowledgment))

    # Extract TCP flags
    flag_urg = (flags & 0x0020) >> 5
    flag_ack = (flags & 0x0010) >> 4
    flag_psh = (flags & 0x0008) >> 3
    flag_rst = (flags & 0x0004) >> 2
    flag_syn = (flags & 0x0002) >> 1
    flag_fin = flags & 0x0001

    print('*****Flags*****')
    print('URG: {}\nACK: {}\nPSH: {}'.format(flag_urg, flag_ack, flag_psh))
    print('RST: {}\nSYN: {}\nFIN:{}'.format(flag_rst, flag_syn, flag_fin))

    if len(raw_data) > 0:
        # HTTP
        if src_port == 80 or dest_port == 80:
            print('*****HTTP Data*****')
            try:
                # Assuming an HTTP class is available for parsing
                http = HTTP(raw_data)
                http_info = str(http.data).split('\n')
                for line in http_info:
                    print(str(line))
            except Exception as e:
                print(f"Error parsing HTTP data: {e}")
        else:
            print('*****TCP Data*****')
            print(format_output_line("", raw_data))


def print_udp_packets_v4(version, header_length, ttl, proto, src, target, data):
    """
    Print details of UDP packets based on IPv4.
    """
    print("*******************UDPv4***********************")
    print('Version: {}\nHeader Length: {}\nTTL: {}'.format(version, header_length, ttl))
    print('protocol: {}\nSource: {}\nTarget: {}'.format(proto, src, target))
    src_port, dest_port, length, data = udp_seg(data)
   
    print('*****UDP Segment*****')
    print('Source Port: {}\nDestination Port: {}\nLength: {}'.format(src_port, dest_port, length))


def print_packets_v6(filter, next_proto, new_packet):
    """
    Print details of IPv6 packets based on the specified filter.
    """
    remaining_packet = ""

    if next_proto == 'ICMPv6' and (not filter or filter[2] == "ICMPv6"):
        remaining_packet = icmpv6_header(new_packet)
    elif next_proto == 'TCP' and (not filter or filter[2] == "TCP"):
        remaining_packet = tcp_header(new_packet)
    elif next_proto == 'UDP' and (not filter or filter[2] == "UDP"):
        remaining_packet = udp_header(new_packet)

    return remaining_packet


def tcp_header(new_packet):
    """
    Print details of TCP headers based on IPv6.
    """
    # Unpack TCP header data
    packet = struct.unpack("!2H2I4H", new_packet[0:20])
    src_port = packet[0]
    dest_port = packet[1]
    sqnc_num = packet[2]
    ackn_num = packet[3]
    data_offset = packet[4] >> 12
    reserved = (packet[4] >> 6) & 0x003F
    tcp_flags = packet[4] & 0x003F
    urg_flag = tcp_flags & 0x0020
    ack_flag = tcp_flags & 0x0010
    push_flag = tcp_flags & 0x0008
    reset_flag = tcp_flags & 0x0004
    syn_flag = tcp_flags & 0x0002
    fin_flag = tcp_flags & 0x0001
    window = packet[5]
    check_sum = packet[6]
    urg_pntr = packet[7]

    print("*******************TCP***********************")
    print("\tSource Port: " + str(src_port))
    print("\tDestination Port: " + str(dest_port))
    print("\tSequence Number: " + str(sqnc_num))
    print("\tAck. Number: " + str(ackn_num))
    print("\tData Offset: " + str(data_offset))
    print("\tReserved: " + str(reserved))
    print("\tTCP Flags: " + str(tcp_flags))

    if urg_flag == 32:
        print("\tUrgent Flag: Set")
    if ack_flag == 16:
        print("\tAck Flag: Set")
    if push_flag == 8:
        print("\tPush Flag: Set")
    if reset_flag == 4:
        print("\tReset Flag: Set")
    if syn_flag == 2:
        print("\tSyn Flag: Set")
    if fin_flag == True:  # Note: fin_flag is already a boolean
        print("\tFin Flag: Set")

    print("\tWindow: " + str(window))
    print("\tChecksum: " + str(check_sum))
    print("\tUrgent Pointer: " + str(urg_pntr))
    print(" ")

    new_packet = new_packet[20:]
    return new_packet


def udp_header(new_packet):
    """
    Print details of UDP headers based on IPv6.
    """
    # Unpack UDP header data
    packet = struct.unpack("!4H", new_packet[0:8])
    src_port = packet[0]
    dest_port = packet[1]
    length = packet[2]
    check_sum = packet[3]

    print("*******************UDP***********************")
    print("\tSource Port: " + str(src_port))
    print("\tDestination Port: " + str(dest_port))
    print("\tLength: " + str(length))
    print("\tChecksum: " + str(check_sum))
    print(" ")

    new_packet = new_packet[8:]
    return new_packet


def icmpv6_header(data):
    """
    Print details of ICMPv6 headers.
    """
    ipv6_icmp_type, ipv6_icmp_code, ipv6_icmp_checksum = struct.unpack(">BBH", data[:4])

    print("*******************ICMPv6***********************")
    print("\tICMPv6 type: %s" % ipv6_icmp_type)
    print("\tICMPv6 code: %s" % ipv6_icmp_code)
    print("\tICMPv6 checksum: %s" % ipv6_icmp_checksum)

    data = data[4:]
    return data


def next_header(ipv6_next_header):
    """
    Get the name of the next header based on its number.
    """
    headers = {
        6: 'TCP',
        17: 'UDP',
        43: 'Routing',
        1: 'ICMP',
        58: 'ICMPv6',
        44: 'Fragment',
        0: 'HOPOPT',
        60: 'Destination',
        51: 'Authentication',
        50: 'Encapsulation'
    }

    return headers.get(ipv6_next_header, str(ipv6_next_header))


def ipv6_header(data, filter):
    """
    Print details of IPv6 headers based on the specified filter.
    """
    ipv6_first_word, ipv6_payload_length, ipv6_next_header, ipv6_hop_limit = struct.unpack(
        ">IHBB", data[0:8])
    ipv6_src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    ipv6_dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

    bin(ipv6_first_word)
    "{0:b}".format(ipv6_first_word)
    version = ipv6_first_word >> 28
    traffic_class = ipv6_first_word >> 16 & 4095
    flow_label = ipv6
    flow_label = ipv6_first_word & 65535

    ipv6_next_header = next_header(ipv6_next_header)
    data = data[40:]

    return data, ipv6_next_header


# Unpack Ethernet Frame
def ethernet_frame(data):
    """
    Unpack Ethernet frame and extract relevant information.
    """
    proto = ""
    ip_header = struct.unpack("!6s6sH", data[:14])
    dst_mac = binascii.hexlify(ip_header[0]).decode('utf-8')
    src_mac = binascii.hexlify(ip_header[1]).decode('utf-8')
    proto_type = ip_header[2]
    next_proto = hex(proto_type)

    if next_proto == '0x800':
        proto = 'IPV4'
    elif next_proto == '0x86dd':
        proto = 'IPV6'

    data = data[14:]

    return dst_mac, src_mac, proto, data


# Unpacks for any ICMP Packet
def icmp_packet(data):
    """
    Unpack ICMP packet and extract relevant information.
    """
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpacks for any UDP Packet
def udp_seg(data):
    """
    Unpack UDP packet and extract relevant information.
    """
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# Unpacks for any IPv4 Packet
def ipv4_packet(data):
    """
    Unpack IPv4 packet and extract relevant information.
    """
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]


# Returns Formatted IP Address
def ipv4(addr):
    """
    Format IPv4 address.
    """
    return '.'.join(map(str, addr))


# Formats the output line
def format_output_line(prefix, string):
    """
    Format output line for display.
    """
    size = 80
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
            return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


if __name__ == "__main__":
    main()
