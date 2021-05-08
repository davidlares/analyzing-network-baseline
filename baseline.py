from scapy import plist
from scapy.all import *
import argparse
import json

def profile_sessions(pcap_reader):
    packets = []
    print('Getting details from packets.')

    # declaring timestamps
    first_timestamp, last_timestamp = None, None
    for packet in pcap_reader:
        if IP not in packet:
            continue
        if TCP not in packet:
            continue
        if not first_timestamp:
            first_timestamp = packet.time
        if not last_timestamp:
            last_timestamp = packet.time
        if packet.time < first_timestamp:
            first_timestamp = packet.time
        elif packet.time > last_timestamp:
            last_timestamp = packet.time

        # appending timestamps (timestamp of the first and last packet) in the packet list
        packets.append(packet)

    # Scapy packet list (python object)
    packets = plist.PacketList(packets)
    print('Analyzing sessions.')

    # grabbing packets sessions
    sessions = packets.sessions()

    # calcuting the profile data
    profile = {'start_timestamp': float(first_timestamp), 'end_timestamp': float(last_timestamp),
               'duration_secs': float(last_timestamp - first_timestamp), 'total_packets': len(packets),
               'total_sessions': len(sessions)}

    # calculating average per second
    profile['avg_pps'] = profile['duration_secs'] / profile['total_packets']

    # calculating ratio
    profile['packets_to_sessions_ratio'] = profile['total_packets'] / profile['total_sessions']
    return profile

if __name__ == "__main__":

    # Wireshark intended protocols available (filtering) -> unencrpyted protocols
    app_filters = {'ftp': 'tcp port 21', 'http': 'tcp port 80', 'telnet': 'tcp port 23'}

    parser = argparse.ArgumentParser(description='This application calculates a network traffic profile for a specific host from a provided PCAP file.')
    parser.add_argument('-a', '--application', help='Application to filter packets for', choices=list(app_filters.keys()))
    parser.add_argument('-i', '--ip', help='IP address to filter packets for (source or destination)', required=True)
    parser.add_argument('-o', '--output', help='Output file to write to')
    parser.add_argument('pcap_file', help='PCAP file to read packets from')
    args = parser.parse_args()

    # handling the application (-a)
    application = args.application
    if application:
        packet_filter = app_filters[application]
        packet_filter = '{} and host {}'.format(packet_filter, args.ip)
    else:
        packet_filter = 'host {}'.format(args.ip)

    # handling pcap file
    pcap_file = args.pcap_file

    # handling output
    output = args.output

    # read and analyze packets
    print('Starting to read packets from file with filter "{}".'.format(packet_filter))

    # pcap reader object
    with PcapReader(tcpdump(pcap_file, args=["-w", "-", packet_filter], getfd=True)) as pcap_reader:
        profile = profile_sessions(pcap_reader) # evaluating the pcap object reader

    # handling (-o mechanism) file
    if output:
        with open(output, 'w') as of:
            json.dump(profile, of, indent=2)
    else:
        print(json.dumps(profile, indent=2))
