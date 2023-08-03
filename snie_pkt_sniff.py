# -*- coding: utf-8 -*-
"""
@author: khandkar
"""
import os.path

from scapy.all import *
import pyshark
import warnings
warnings.filterwarnings(action= 'ignore')
import multiprocessing

load_layer("tls")
from scapy.layers.inet import IP, TCP
import csv
from rich.pretty import pprint

pkt_count = 0
pkts = []

itime = time.time()
capture = sniff(count=1)
is_ps_stop = Event()

tcp_count = 0
udp_count = 0
quic_count = 0
total_count = 0

header = ["Time", "TLS version", "SNI", "Source IP address", "Destination IP address", "Source port",
          "Destination Port", "Protocol", "Downloaded Data size (bytes)", "TLS session duration (s)",
          "Foreground/Background", "SSL Certificate information"]

csv_header = {"Time": "Time", "TLS version": "TLS version", "SNI": "SNI", "Source IP address": "Source IP address",
              "Destination IP address": "Destination IP address", "Source port": "Source port",
              "Destination Port": "Destination Port", "Protocol": "Protocol",
              "Downloaded Data size (bytes)": "Downloaded Data size (bytes)",
              "TLS session duration (s)": "TLS session duration (s)",
              "Foreground/Background": "Foreground/Background",
              "SSL Certificate information": "SSL Certificate information",
              }

header_index = {
    "Initial Time": 0,
    "TLS version": 1,
    "SNI": 2,
    "Source IP address": 3,
    "Destination IP address": 4,
    "Source port": 5,
    "Destination Port": 6,
    "Protocol": 7,
    "Packet length (Tx)": 8,
    "Packet length (Rx)": 9,
    "Packet length (All)": 10,
    "Time (Tx)": 11,
    "Time (Rx)": 12,
    "Time (All)": 13
}

combined_header_index = {
    "Time": 0,
    "TLS version": 1,
    "SNI": 2,
    "Source IP address": 3,
    "Destination IP address": 4,
    "Source port": 5,
    "Destination Port": 6,
    "Protocol": 7,
    "TLS session duration (s)": 8,
    "Downloaded Data size (bytes) Up": 9,
    "Downloaded Data size (bytes) Down": 10,
    "Downloaded Data size (bytes) Total": 11,
}

processed_data = {}

def get_flow(protocol, ip_src, ip_dst, port_src, port_dst):
    dir = 0

    # if protocol not in ["TCP", "UDP", "QUIC"]:
    #     return "NA", dir
    
    if ip_src > ip_dst:
        ip_src, ip_dst = ip_dst, ip_src
        port_src, port_dst = port_dst, port_src
        dir = 1

    if ip_src == ip_dst and port_src > port_dst:
        dir = 1
        port_src, port_dst = port_dst, port_src

    return (protocol, ip_src, ip_dst, port_src, port_dst), dir

def generate_tcp_dict_key(packet):
    return get_flow("TCP", str(packet['ip'].src), str(packet['ip'].dst), str(packet['tcp'].srcport), str(packet['tcp'].dstport))

def generate_udp_dict_key(packet):
    return get_flow("UDP", str(packet['ip'].src), str(packet['ip'].dst), str(packet['udp'].srcport), str(packet['udp'].dstport))

def generate_quic_dict_key(saddr, daddr, sport, dport):
    return get_flow("QUIC", str(saddr), str(daddr), str(sport), str(dport))

def generate_other_dict_key(packet):
    # return (str(packet['ip'].proto), str(packet['ip'].src), str(packet['ip'].dst))
    return get_flow(str(packet['ip'].proto), str(packet['ip'].src), str(packet['ip'].dst), str(packet['ip'].src_host), str(packet['ip'].dst_host))
    

def snie_sniff_packets(STO, fname):
    global capture
    if not os.path.exists('./Input_data'):
        os.system('mkdir Input_data')
    fname = "./Input_data/"+ fname
    if not os.path.exists(fname):
        comm = 'echo > ' + fname
        os.system(comm)
    print("[+] Sniffing packets for " + str(STO) + " seconds")
    capture = sniff(stop_filter=is_ps_stop.is_set(), timeout=STO)
    wrpcap(fname, capture)



def snie_read_raw_pkts(fname):
    print("[+] Reading packets from " + str(fname))
    # pkts = pyshark.FileCapture(fname, display_filter="(ip.addr eq 10.7.55.152 and ip.addr eq 108.159.78.199) and (tcp.port eq 63516 and tcp.port eq 443)")
    pkts = pyshark.FileCapture(fname)
    print("[+] Reading done")
    return pkts

def snie_get_tr_proto(ip):
    import socket
    #  if ip == str(socket.IPPROTO_TCP) or ip == str(socket.IPPROTO_UDP):
    #    print(str(ip) + " : ")
    if ip == str(socket.IPPROTO_TCP):
        return "TCP"
    elif ip == str(socket.IPPROTO_UDP):
        return "UDP"
    else:
        return str(ip)


def snie_handle_udp_packet(packet):
    if not 'udp' in packet:
        return
    key, dir = generate_udp_dict_key(packet)
    if generate_udp_dict_key(packet) in processed_data.keys():
        row = processed_data[key]
    else:
        if dir == 0:
            src_ip, src_port = str(packet['ip'].src), str(packet['udp'].srcport)
            dst_ip, dst_port = str(packet['ip'].dst), str(packet['udp'].dstport)
        else:
            src_ip, src_port = str(packet['ip'].dst), str(packet['udp'].dstport)
            dst_ip, dst_port = str(packet['ip'].src), str(packet['udp'].srcport)

        row = {
            "Initial Time": str(packet.sniff_timestamp),
            "TLS version": "NA",
            "SNI": "NA",
            "Source IP address": src_ip,
            "Destination IP address": dst_ip,
            "Source port": src_port,
            "Destination Port": dst_port,
            "Protocol": snie_get_tr_proto(packet['ip'].proto),
            "Packet length (Tx)": [],
            "Packet length (Rx)": [],
            "Packet length (All)": [],
            "Time (Tx)": [],
            "Time (Rx)": [],
            "Time (All)": []
        }

    psize = int(packet['udp'].length)
    if dir == 0:
        row['Packet length (Tx)'].append(psize)
        row["Time (Tx)"].append(packet.sniff_timestamp)
    else:
        row['Packet length (Rx)'].append(psize)
        row["Time (Rx)"].append(packet.sniff_timestamp)
    
    row['Packet length (All)'].append(psize)
    row["Time (All)"].append(packet.sniff_timestamp)    
    processed_data[key] = row


def snie_handle_other_packet(packet):
    key, dir = generate_other_dict_key(packet)
    if key in processed_data.keys():
        row = processed_data[key]
    else:
        if dir == 0:
            src_ip, src_port = str(packet['ip'].src), str(packet['ip'].src_host)
            dst_ip, dst_port = str(packet['ip'].dst), str(packet['ip'].dst_host)
        else:
            src_ip, src_port = str(packet['ip'].dst), str(packet['ip'].dst_host)
            dst_ip, dst_port = str(packet['ip'].src), str(packet['ip'].src_host)

        row = {
            "Initial Time": str(packet.sniff_timestamp),
            "TLS version": "NA",
            "SNI": "NA",
            "Source IP address": src_ip,
            "Destination IP address": dst_ip,
            "Source port": src_port,
            "Destination Port": dst_port,
            "Protocol": snie_get_tr_proto(packet['ip'].proto),
            "Packet length (Tx)": [],
            "Packet length (Rx)": [],
            "Packet length (All)": [],
            "Time (Tx)": [],
            "Time (Rx)": [],
            "Time (All)": []
        }
    psize = 0
    if dir == 0:
        row['Packet length (Tx)'].append(psize)
        row["Time (Tx)"].append(packet.sniff_timestamp)
    else:
        row['Packet length (Rx)'].append(psize)
        row["Time (Rx)"].append(packet.sniff_timestamp)
    row['Packet length (All)'].append(psize)
    row["Time (All)"].append(packet.sniff_timestamp)

    processed_data[key] = row


def snie_get_tls_proto_info(packet):
    from pyshark.packet.fields import LayerField
    tls_extension_version = "0x0a"
    tls_version = "0x0a"
    tls_handshake_type = None
    sni_info = ["NA", ["NA"]]
    if int(packet['tcp'].dstport) == 443 or int(packet['tcp'].srcport) == 443:  # Encrypted TCP packet
        if 'tls' in packet:
            for layer in packet:
                if layer.layer_name == "tls":
                    llayer = dir(layer)
                    if "handshake_type" in llayer:
                        tls_handshake_type = layer.handshake_type

                    if "handshake_extensions_supported_version" in llayer:
                        tls_extension_version = layer.handshake_extensions_supported_version
                    if "record_version" in llayer:
                        tls_version = layer.record_version
                    if 'handshake_extensions_server_name' in llayer:
                        sni = layer.handshake_extensions_server_name.showname.replace("Server Name: ", "")
                        sni_info[1] = sni
                    final_version = max(int(str(tls_extension_version),16),int(str(tls_version),16))
                    if final_version != 0x0a and tls_handshake_type == "2":
                        final_version = str(hex(final_version))
                        final_version = f"{final_version[:2]}0{final_version[2:]}"
                        sni_info[0] = final_version

    return sni_info

def snie_handle_tcp(packet):
    if not 'tcp' in packet:
        return
    
    key, dir = generate_tcp_dict_key(packet)
    if key in processed_data.keys():
        row = processed_data[key]

        sni_info = snie_get_tls_proto_info(packet)
        
        if sni_info[0] != "NA":
            row["TLS version"] = sni_info[0]

        for sni in sni_info[1]:
            if "NA" in row["SNI"]:
                row["SNI"] = str(sni)
            else:
                if sni != "NA":
                    row["SNI"] += " , " + str(sni)
    else:
        sni_info = snie_get_tls_proto_info(packet)
        if dir == 0:
            src_ip, src_port = str(packet['ip'].src), str(packet['tcp'].srcport)
            dst_ip, dst_port = str(packet['ip'].dst), str(packet['tcp'].dstport)
        else:
            src_ip, src_port = str(packet['ip'].dst), str(packet['tcp'].dstport)
            dst_ip, dst_port = str(packet['ip'].src), str(packet['tcp'].srcport)

        sni_field = "NA"

        for sni in sni_info[1]:
            if "NA" in sni_field:
                sni_field = str(sni)
            else:
                if sni != "NA":
                    sni_field += " , " + str(sni)

        row = {
            "Initial Time": str(packet.sniff_timestamp),
            "TLS version": sni_info[0],
            "SNI": sni,
            "Source IP address": src_ip,
            "Destination IP address": dst_ip,
            "Source port": src_port,
            "Destination Port": dst_port,
            "Protocol": snie_get_tr_proto(packet['ip'].proto),
            "Packet length (Tx)": [],
            "Packet length (Rx)": [],
            "Packet length (All)": [],
            "Time (Tx)": [],
            "Time (Rx)": [],
            "Time (All)": []
        }
       
    psize = int(packet['tcp'].len)

    if dir == 0:
        row['Packet length (Tx)'].append(psize)
        row["Time (Tx)"].append(packet.sniff_timestamp)
    else:
        row['Packet length (Rx)'].append(psize)
        row["Time (Rx)"].append(packet.sniff_timestamp)
    row['Packet length (All)'].append(psize)
    row["Time (All)"].append(packet.sniff_timestamp)

    processed_data[key] = row

def snie_record_quic_info(saddr, daddr, sport, dport, sni, len, tstamp, tls_version):
    key, dir = generate_quic_dict_key(saddr, daddr, sport, dport)
    if key in processed_data.keys():
        row = processed_data[key]
    else:
        if dir == 0:
            src_ip, src_port = str(saddr), str(sport)
            dst_ip, dst_port = str(daddr), str(dport)
        else:
            src_ip, src_port = str(daddr), str(dport)
            dst_ip, dst_port = str(saddr), str(sport)

        row = {
            "Initial Time": str(tstamp),
            "TLS version": tls_version,
            "SNI": str(sni),
            "Source IP address": src_ip,
            "Destination IP address": dst_ip,
            "Source port": src_port,
            "Destination Port": dst_port,
            "Protocol": "QUIC",
            "Packet length (Tx)": [],
            "Packet length (Rx)": [],
            "Packet length (All)": [],
            "Time (Tx)": [],
            "Time (Rx)": [],
            "Time (All)": []
        }
    
    if dir == 0:
        row['Packet length (Tx)'].append(len)
        row["Time (Tx)"].append(tstamp)
    else:
        row['Packet length (Rx)'].append(len)
        row["Time (Rx)"].append(tstamp)
    row['Packet length (All)'].append(len)
    row["Time (All)"].append(tstamp)

    processed_data[key] = row

def handle_packet(packet):
    global total_count
    global tcp_count
    global udp_count
    global quic_count

    if 'ip' in packet:
            try:
                if 'quic' in packet:  # QUIC packet
                    from snie_quic import sne_quic_extract_pkt_info
                    saddr, daddr, sport, dport, sni, qlen, tstamp, tls_version = sne_quic_extract_pkt_info(packet)
                    snie_record_quic_info(saddr, daddr, sport, dport, sni, qlen, tstamp, tls_version)
                    quic_count += 1
                elif 'tcp' in packet:
                    snie_handle_tcp(packet)
                    tcp_count += 1
                elif 'udp' in packet:  # UDP packet
                    snie_handle_udp_packet(packet)
                    udp_count += 1
                else:
                    snie_handle_other_packet(packet)
            except KeyboardInterrupt:
                print("Execution interrupted")
                exit(0)
            total_count += 1
            # print("[+] Number of packets processed : TCP = " + str(tcp_count) + "  UDP = " + str(udp_count) + \
            #       "  QUIC = " + str(quic_count) + "  Total = " + str(total_count), end = "\r")

def snie_process_data_dict(outputfname):
    # processed_data_list = []

    # for key in processed_data:
    #     processed_data_list.append(processed_data[key])       
    
    snie_sanitize_data()
    pprint(processed_data)

    # combined_list  = combine_flows(processed_data_list)
    # write_to_csv(combined_list, outputfname, list(combined_header_index.keys()))

    # create_sni_list(combined_list, outputfname.replace(".csv", "_sni.csv"))

def create_sni_list(data_list, output_fname):
    print("[+] Creating SNI list")
    d = {}
    header = {
        "SNI": 0,
        "Protocol": 1,
        "Downloaded Data size (bytes) Up": 2,
        "Downloaded Data size (bytes) Down": 3,
        "Downloaded Data size (bytes) Total": 4,
        "TLS session duration (s)": 5,
    }

    for line in data_list:
        if line[combined_header_index["SNI"]] == "NA":
            continue

        key = line[combined_header_index["SNI"]], line[combined_header_index["Protocol"]]
        if key not in d.keys():
            d[key] = [
                line[combined_header_index["SNI"]],
                line[combined_header_index["Protocol"]],
                line[combined_header_index["Downloaded Data size (bytes) Up"]],
                line[combined_header_index["Downloaded Data size (bytes) Down"]],
                line[combined_header_index["Downloaded Data size (bytes) Total"]],
                line[combined_header_index["TLS session duration (s)"]]
            ]
        else:
            l = d[key]
            l[header["Downloaded Data size (bytes) Up"]] += line[combined_header_index["Downloaded Data size (bytes) Up"]]
            l[header["Downloaded Data size (bytes) Down"]] += line[combined_header_index["Downloaded Data size (bytes) Down"]]
            l[header["Downloaded Data size (bytes) Total"]] += line[combined_header_index["Downloaded Data size (bytes) Total"]]
            l[header["TLS session duration (s)"]] += line[combined_header_index["TLS session duration (s)"]]
            d[key] = l
        
    new_data_list = []
    for key in d:
        new_data_list.append(d[key])
    
    write_to_csv(new_data_list, output_fname, list(header.keys()))


    

def snie_process_raw_packets(raw_pkts, outputfname, MAX_PKT_COUNT):
    for packet in raw_pkts:
        handle_packet(packet)
        if MAX_PKT_COUNT != "NA" and pkt_count >= MAX_PKT_COUNT:
            break
    
    snie_process_data_dict(outputfname)


def snie_sanitize_data():
    # Format SNI field
    print("[+] Sanitizing Data")
    for key in processed_data.keys():
        row = processed_data[key]
    
        if row["SNI"] != "NA":
            sni = row["SNI"]
            sni = sni.replace(" ", "")
            snil = list(sni.replace(",", ""))
            sni = ""
            for item in snil:
                if item != ",":
                    sni += item
            row["SNI"] = sni
        processed_data[key] = row

def write_to_csv(data_list, fname, header_list):
    print("[+] Writing to", fname)
    with open(fname, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(header_list)
        for line in data_list:
            if line == []:
                continue
            writer.writerow(line)



def snie_process_packets(MAX_PKT_COUNT, inputfname, outputfname):
    # Just for making sure we have permission
    f1 = open(outputfname, 'w', newline='')
    f1.close()

    # Just for making sure we have permission
    f1 = open(outputfname.replace(".csv", "_sni.csv"), 'w', newline='')
    f1.close()
    
    raw_pkts = snie_read_raw_pkts(inputfname)
    if raw_pkts is None:
        print("Too few packets to sniff")
    
    try:
        snie_process_raw_packets(raw_pkts, outputfname, MAX_PKT_COUNT)
    except (KeyboardInterrupt, SystemExit):
        pass

    return




def sniff_packets_live(STO, fname, sender):
    def prn_analyse_packet(packet):
        sender.send(packet)

    global capture
    if not os.path.exists('./Input_data'):
        os.system('mkdir Input_data')
    fname = "./Input_data/"+ fname
    if not os.path.exists(fname):
        comm = 'echo > ' + fname
        os.system(comm)
    print("[+] Sniffing packets for " + str(STO) + " seconds")

    capture = pyshark.LiveCapture(output_file=fname, )
    capture.sniff(timeout=STO)
    try:
        capture.apply_on_packets(prn_analyse_packet, timeout=STO)
    except TimeoutError:
        pass

    capture.clear()
    capture.close()
    print("[+] Sniffing done")
    sender.send("STOP")

def process_live_packets(outputfname, receiver):
    while True:
        packet = receiver.recv()
        
        if packet == "STOP":
            break

        handle_packet(packet)

    print("[+] Number of packets processed : TCP = " + str(tcp_count) + "  UDP = " + str(udp_count) + \
                  "  QUIC = " + str(quic_count) + "  Total = " + str(total_count), end = "\r")
    snie_process_data_dict(outputfname)

def snie_sniff_and_analyse_packets(STO, fname, outputfname, verbose=False):
    global capture

    sender, receiver = multiprocessing.Pipe()

    p1 = multiprocessing.Process(target=sniff_packets_live, args=(STO, fname, sender))
    p2 = multiprocessing.Process(target=process_live_packets, args=(outputfname, receiver))

    p1.start()
    p2.start()

    p1.join()
    p2.join()