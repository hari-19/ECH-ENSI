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

flow_itr = 0
flow_map = {}

processed_data = {}

def generate_row_dict(processed_packet_list):
    row_dict = {}
    for key in header_index.keys():
        row_dict[key] = processed_packet_list[header_index[key]]

    return row_dict

def generate_list_from_dict(processed_packet_dict):
    row_list = []
    for key in header_index.keys():
        row_list.append(processed_packet_dict[key])

    return row_list

def get_flow(protocol, ip_src, ip_dst, port_src, port_dst):
    dir = 0

    if protocol not in ["TCP", "UDP", "QUIC"]:
        return "NA", dir
    
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
    return ("UDP", str(packet['ip'].src), str(packet['ip'].dst), str(packet['udp'].srcport), str(packet['udp'].dstport))

def generate_quic_dict_key(saddr, daddr, sport, dport):
    return get_flow("QUIC", str(saddr), str(daddr), str(sport), str(dport))

def generate_other_dict_key(packet):
    return (str(packet['ip'].proto), str(packet['ip'].src), str(packet['ip'].dst))
    

data_size = {}


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


def snie_get_udppayloadlen(packet):
    t_len = int(packet['udp'].length)
    return t_len


def snie_get_otherpayloadlen(packet):
    t_len = int(0)
    return t_len

def snie_get_udp_prot_info(packet):
    sni_info = []
    sni_info.append(str(packet.sniff_timestamp))
    sni_info.append("NA")
    sni_info.append("NA")
    sni_info.append(str(packet['ip'].src))
    sni_info.append(str(packet['ip'].dst))
    sni_info.append(str(packet['udp'].srcport))
    sni_info.append(str(packet['udp'].dstport))
    sni_info.append(snie_get_tr_proto(packet['ip'].proto))
    psize = snie_get_udppayloadlen(packet)
    sni_info.append(str(psize))
    sni_info.append("NA")
    sni_info.append(str(0))
    sni_info.append(str(0))
    return sni_info

def snie_handle_udp_packet(packet):
    if not 'udp' in packet:
        return
    
    if generate_udp_dict_key(packet) in processed_data.keys():
        row = generate_row_dict(processed_data[generate_udp_dict_key(packet)])
        osize = int(row["Downloaded Data size (bytes)"])
        psize = snie_get_udppayloadlen(packet)
        dsize = osize + psize
        row['Downloaded Data size (bytes)'] = dsize
        processed_data[generate_udp_dict_key(packet)] = generate_list_from_dict(row)
    else:
        sni_info = snie_get_udp_prot_info(packet)
        processed_data[generate_udp_dict_key(packet)] = sni_info


def snie_get_other_prot_info(packet):
    sni_info = []
    sni_info.append(str(packet.sniff_timestamp))
    sni_info.append("NA")
    sni_info.append("NA")
    sni_info.append(str(packet['ip'].src))
    sni_info.append(str(packet['ip'].dst))
    sni_info.append(str(packet['ip'].src_host))
    sni_info.append(str(packet['ip'].dst_host))
    sni_info.append(snie_get_tr_proto(packet['ip'].proto))
    psize = 0
    sni_info.append(str(psize))
    sni_info.append("NA")
    sni_info.append(str(0))
    sni_info.append(str(0))
    return sni_info

def snie_handle_other_packet(packet):
    if generate_other_dict_key(packet) in processed_data.keys():
        row = generate_row_dict(processed_data[generate_other_dict_key(packet)])
        osize = int(row["Downloaded Data size (bytes)"])
        psize = snie_get_otherpayloadlen(packet)
        dsize = osize + psize
        row['Downloaded Data size (bytes)'] = dsize
        processed_data[generate_other_dict_key(packet)] = generate_list_from_dict(row)
    else:
        sni_info = snie_get_other_prot_info(packet)
        processed_data[generate_other_dict_key(packet)] = sni_info


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

        row = {
            "Initial Time": str(packet.sniff_timestamp),
            "TLS version": sni_info[0],
            "SNI": sni_info[1],
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
                    return
                    snie_handle_tcp(packet)
                    tcp_count += 1
                elif 'udp' in packet:  # UDP packet
                    return
                    snie_handle_udp_packet(packet)
                    udp_count += 1
                else:
                    return
                    snie_handle_other_packet(packet)
            except KeyboardInterrupt:
                print("Execution interrupted")
                exit(0)
            total_count += 1
            print("[+] Number of packets processed : TCP = " + str(tcp_count) + "  UDP = " + str(udp_count) + \
                  "  QUIC = " + str(quic_count) + "  Total = " + str(total_count), end = "\r")

def snie_process_data_dict(outputfname):
    # processed_data_list = []

    # for key in processed_data:
    #     processed_data_list.append(processed_data[key])       
    
    pprint(processed_data)
    # snie_sanitize_data_list(processed_data_list)
    # add_flow_id(processed_data_list)
    # update_tls(processed_data_list)
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


    
def combine_flows(data_list):
    print("[+] Combining flows")
    d = {}
    for line in data_list:
        if line[header_index["Flow ID"]] not in d.keys():
            new_list = [
                line[header_index["Time"]],
                line[header_index["TLS version"]],
                line[header_index["SNI"]],
                line[header_index["Source IP address"]],
                line[header_index["Destination IP address"]],
                line[header_index["Source port"]],
                line[header_index["Destination Port"]],
                line[header_index["Protocol"]],
                line[header_index["TLS session duration (s)"]],
                0,
                0,
                0            
            ]

            if line[header_index["Direction"]] == 0:
                new_list[combined_header_index["Downloaded Data size (bytes) Up"]] = int(line[header_index["Downloaded Data size (bytes)"]])
            else:
                new_list[combined_header_index["Downloaded Data size (bytes) Down"]] = int(line[header_index["Downloaded Data size (bytes)"]])
            
            new_list[combined_header_index["Downloaded Data size (bytes) Total"]] += int(line[header_index["Downloaded Data size (bytes)"]])

            d[line[header_index["Flow ID"]]] = new_list
        else:
            new_list = d[line[header_index["Flow ID"]]]
            # if line[header_index["TLS session duration (s)"]] > new_list[combined_header_index["TLS session duration (s)"]]:
            #     new_list[combined_header_index["TLS session duration (s)"]] = line[header_index["TLS session duration (s)"]]

            if line[header_index["Direction"]] == 0:
                new_list[combined_header_index["Downloaded Data size (bytes) Up"]] = int(line[header_index["Downloaded Data size (bytes)"]])
            else:
                new_list[combined_header_index["Downloaded Data size (bytes) Down"]] = int(line[header_index["Downloaded Data size (bytes)"]])
            
            new_list[combined_header_index["Downloaded Data size (bytes) Total"]] += int(line[header_index["Downloaded Data size (bytes)"]])

            d[line[header_index["Flow ID"]]] = new_list
    
    new_data_list = []
    for key in d:
        new_data_list.append(d[key])

    new_data_list.sort(key=lambda x: x[0])

    return new_data_list


def snie_process_raw_packets(raw_pkts, outputfname, MAX_PKT_COUNT):
    for packet in raw_pkts:
        handle_packet(packet)
        if MAX_PKT_COUNT != "NA" and pkt_count >= MAX_PKT_COUNT:
            break
    
    snie_process_data_dict(outputfname)

def sanitize_sni(sni):
    if sni != "NA":
        sni = sni.replace(" ", "")
        snil = list(sni.replace(",", ""))
        sni = ""
        for item in snil:
            if item != ",":
                sni += item

def snie_sanitize_data_list(data_list):
    print("[+] Sanitizing Data")
    for line in data_list:
        if line == []:
            continue
    
        if isinstance(line[1], set):
            tls_version = ""
            for item in line[1]:
                if item != "NA":
                    tls_version += item + ", "
            line[1] = tls_version
            if line[1] == "":
                line[1] = "NA"
    
        if line[2] != "NA":
            sni = line[2]
            sni = sni.replace(" ", "")
            snil = list(sni.replace(",", ""))
            sni = ""
            for item in snil:
                if item != ",":
                    sni += item
            line[2] = sni


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

def get_flow_id(protocol, ip_src, ip_dst, port_src, port_dst):
    global flow_itr
    global flow_map

    dir = 0

    if protocol not in ["TCP", "UDP", "QUIC"]:
        return "NA", dir
    
    if ip_src > ip_dst:
        ip_src, ip_dst = ip_dst, ip_src
        port_src, port_dst = port_dst, port_src
        dir = 1

    if ip_src == ip_dst and port_src > port_dst:
        dir = 1
        port_src, port_dst = port_dst, port_src

    flow_id = flow_map.get((protocol, ip_src, ip_dst, port_src, port_dst), None)

    if(flow_id):
        return flow_id, dir
    
    flow_id = flow_itr
    flow_map[(protocol, ip_src, ip_dst, port_src, port_dst)] = flow_id

    flow_itr += 1

    return flow_id, dir

def add_flow_id(data_list):
    header_index["Flow ID"] = len(header_index)
    header_index["Direction"] = len(header_index)
    for line in data_list:
        if line == []:
            continue
        flow_id, dir = get_flow_id(line[header_index["Protocol"]], line[header_index["Source IP address"]], line[header_index["Destination IP address"]], line[header_index["Source port"]], line[header_index["Destination Port"]])
        line.append(flow_id)
        line.append(dir)

def update_tls(data_list):
    tls_info_map = {}

    for data in data_list:
        tls_info = tls_info_map.get(data[header_index["Flow ID"]], ("NA", "NA"))
        if data[header_index["TLS version"]] != "NA":
            tls_info = (data[header_index["TLS version"]], tls_info[1])
        
        if data[header_index["SNI"]] != "NA":
            tls_info = (tls_info[0], data[header_index["SNI"]])
        
        tls_info_map[data[header_index["Flow ID"]]] = tls_info
    
    for data in data_list:
        tls_info = tls_info_map.get(data[header_index["Flow ID"]], ("NA", "NA"))
        data[header_index["TLS version"]] = tls_info[0]
        data[header_index["SNI"]] = tls_info[1]



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