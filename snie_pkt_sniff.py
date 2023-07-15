# -*- coding: utf-8 -*-
"""
@author: khandkar
"""
import os.path

from scapy.all import *
import pyshark
import warnings
warnings.filterwarnings(action= 'ignore')

load_layer("tls")
from scapy.layers.inet import IP, TCP
import csv
from rich.pretty import pprint
STO = 30 # Sniffing period in Seconds

pkt_count = 0
pkts = []

itime = time.time()
capture = sniff(count=1)
is_ps_stop = Event()
tcp_count = 0
udp_count = 0
quic_count = 0

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
    "Time": 0,
    "TLS version": 1,
    "SNI": 2,
    "Source IP address": 3,
    "Destination IP address": 4,
    "Source port": 5,
    "Destination Port": 6,
    "Protocol": 7,
    "Downloaded Data size (bytes)": 8,
    "TLS session duration (s)": 9,
    "Foreground/Background": 10,
    "SSL Certificate information": 11
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


def generate_tcp_dict_key(packet):
    return "TCP" + "-" + str(packet['ip'].src) + "-" +str(packet['ip'].dst) + "-" +str(packet['tcp'].srcport) + "-" + str(packet['tcp'].dstport)

def generate_udp_dict_key(packet):
    return "UDP" + "-" + str(packet['ip'].src) + "-" +str(packet['ip'].dst) + "-" +str(packet['udp'].srcport) + "-" + str(packet['udp'].dstport)

def generate_quic_dict_key(saddr, daddr, sport, dport):
    return "QUIC" + "-" + str(saddr) + "-" + str(daddr) + "-" + str(sport) + "-" + str(dport)

def generate_other_dict_key(packet):
    return str(packet['ip'].proto) + "-" + str(packet['ip'].src) + "-" + str(packet['ip'].dst)
    

data_size = {}


def snie_get_host():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    host = s.getsockname()[0]
    print(host)
    return host


def snie_sniff_packets(STO):
    global capture
    print("Packet sniffer started...")
    if not os.path.exists('./Input_data'):
        os.system('mkdir Input_data')
    fname = "./Input_data/pkts_" + str(STO) + ".pcap"
    if not os.path.exists(fname):
        comm = 'echo > ' + fname
        os.system(comm)
    capture = sniff(stop_filter=is_ps_stop.is_set(), timeout=STO)
    wrpcap(fname, capture)


def snie_read_raw_pkts(STO, fname):
    if fname == None:
        fname = "./Input_data/pkts_" + str(STO) + ".pcap"
    print("[+] Reading packets from " + str(fname))
    # pkts = pyshark.FileCapture(fname, display_filter="(ip.addr eq 10.7.55.152 and ip.addr eq 108.159.78.199) and (tcp.port eq 63516 and tcp.port eq 443)")
    pkts = pyshark.FileCapture(fname)
    print("[+] Reading done")
    return pkts

TLS_VERSIONS_REVRRSE_MAP = {
    # SSL
    "SSL_2_0": 0x0002,
    "SSL_3_0": 0x0300 ,
    # TLS:
    "TLS_1_0": 0x0301,
    "TLS_1_1": 0x0302,
    "TLS_1_2": 0x0303,
    "TLS_1_3": 0x0304,
    # DTLS
    "PROTOCOL_DTLS_1_0_OPENSSL_PRE_0_9_8f": 0x0100,
    "TLS_1_3_DRAFT_16": 0x7f10,
    "TLS_1_3_DRAFT_18": 0x7f12,
    "DTLS_1_0": 0xfeff,
    "DTLS_1_1": 0xfefd,
    # Misc
    "Reserved (GREASE)": 0x0eaea,
}

TLS_VERSIONS = {
    # SSL
    "0x0002": "SSL_2_0",
    "0x0300": "SSL_3_0",
    # TLS:
    "0x0301": "TLS_1_0",
    "0x0302": "TLS_1_1",
    "0x0303": "TLS_1_2",
    "0x0304": "TLS_1_3",
    # DTLS
    "0x0100": "PROTOCOL_DTLS_1_0_OPENSSL_PRE_0_9_8f",
    "0x7f10": "TLS_1_3_DRAFT_16",
    "0x7f12": "TLS_1_3_DRAFT_18",
    "0xfeff": "DTLS_1_0",
    "0xfefd": "DTLS_1_1",
}


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


def snie_get_tcppayloadlen(packet):
    t_len = int(packet['tcp'].len)
    return t_len*8


def snie_get_udppayloadlen(packet):
    t_len = int(packet['udp'].length)
    return t_len*8


def snie_get_otherpayloadlen(packet):
    t_len = int(0)
    return t_len*8


def snie_update_datasize(packet):
    if not packet.haslayer('TCP'):
        return
    fe = open("./Output_data/e.txt", "a")
    f2 = open('./Output_data/snie_temp.csv', 'a', newline='')
    writer = csv.writer(f2)
    dwriter = csv.DictWriter(f2, fieldnames=csv_header)
    flow_id = str(packet['ip'].src) + "_" + str(packet['ip'].dst) + "_" + str(packet['tcp'].sport) + "_" \
              + str(packet['tcp'].dport)
    # print("Flow id : " + str(flow_id) + str(reader))
    f1 = open('./Output_data/snie.csv', 'r')
    reader = csv.reader(f1)
    dreader = csv.DictReader(f1, fieldnames=csv_header)
    for row in dreader:
        output_data = " P : " + str(packet['ip'].src) + ":" + str(packet['ip'].dst) + ":" + str(packet['tcp'].sport) + ":" + \
                      str(packet['tcp'].dport) + "\n"
        output_data += " F : " + row["Source IP address"] + ":" + row["Destination IP address"] + ":" + \
                       row["Source port"] + ":" + row["Destination Port"] + "\n"
        fe.write(output_data)
        if "Protocol" == row["Protocol"]:
            continue
        if "TCP" != str(row["Protocol"]):
            dwriter.writerow(row)
            continue
        if ((str(packet['ip'].src) == row["Source IP address"] and
             str(packet['ip'].dst) == row["Destination IP address"]) ) and \
                ((str(packet['tcp'].sport) == row["Source port"] and
                  str(packet['tcp'].dport) == row["Destination Port"])):
            osize = int(row["Downloaded Data size (bytes)"])
            ti = float(row['Time'])
            # print("I time : " + str(ti))
            # print("osize : " + str(osize))
            psize = snie_get_tcppayloadlen(packet)
            # print("psize = " + str(psize))
            dsize = osize + psize
            # print("new size " + str(dsize))
            row['Downloaded Data size (bytes)'] = dsize
            te = packet.sniff_timestamp
            # print("E time : " + str(te))
            tdiff = te - ti
            # print("Diff = " + str(tdiff))
            tdiff = tdiff.total_seconds()
            # print("DiffS = " + str(tdiff))
            row["TLS session duration (s)"] = tdiff
            dwriter.writerow(row)
        else:
            # print("Not Updated row : " + str(row))
            dwriter.writerow(row)
    f1.close()
    f2.close()
    os.chdir('Output_data')
    os.system('del snie.csv')
    os.system('ren snie_temp.csv snie.csv')
    os.chdir('..')

    fe.close()


def snie_get_quic_prot_info(saddr, daddr, sport, dport, sni, len, tstamp, tls_version):
    sni_info = []
    sni_info.append(str(tstamp))
    sni_info.append(str(TLS_VERSIONS.get(tls_version, "NA")))
    sni_info.append(str(sni))
    sni_info.append(str(saddr))
    sni_info.append(str(daddr))
    sni_info.append(str(sport))
    sni_info.append(str(dport))
    sni_info.append("QUIC")
    psize = str(len)
    sni_info.append(str(psize))
    sni_info.append(str(0))
    sni_info.append(str(0))
    sni_info.append(str(0))
    return sni_info


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
    print("Other packet : " + str(dir(packet['ip'])))
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




def snie_get_tcp_prot_info(packet):
    sni_info = []
    sni_info.append(str(packet.sniff_timestamp))
    sni_info.append("NA")
    sni_info.append("NA")
    sni_info.append(str(packet['ip'].src))
    sni_info.append(str(packet['ip'].dst))
    sni_info.append(str(packet['tcp'].srcport))
    sni_info.append(str(packet['tcp'].dstport))
    sni_info.append(snie_get_tr_proto(packet['ip'].proto))
    psize = snie_get_tcppayloadlen(packet)
    sni_info.append(str(psize))
    sni_info.append("NA")
    sni_info.append(str(0))
    sni_info.append(str(0))
    return sni_info


def snie_fill_cert_info(tls_msg):
    cert = "NA"
    print("Certificate message detected")
    clen = tls_msg.certslen
    print("Certificate length = " + str(clen))
    for cert in tls_msg.certs:
        print(cert)


def snie_fill_ch_info(fp, tls_msg, sni_info):
    #print("Printing TLS SNI info" + "\n")
    #print(tls_msg)
    #exit(0)
    ver = TLS_VERSIONS.get(tls_msg.version, "NA")
    sni_info[1] = str(ver)
    snil = ["NA"]
    for sniinfo in tls_msg['TLS_Ext_ServerName'].servernames:
        sni = ""
        #print("SNI Info per packet " + str(ver) + "\n")
        if True: #ver != "TLS_1_3":
            sni = sniinfo.servername.decode('utf-8')
            output_data = str(sni) + "\n"
            fp.write(output_data)
            #print(output_data + "\n")
        fe = open("./Output_data/e.txt", "a")
        fe.write("SNI added " + str(sni))
        fe.close()
        f1 = open('./Output_data/snie_temp.csv', 'a', newline='')
        if snil[0] == "NA":
            snil[0] = str(sni)
        else:
            snil.append(str(sni))
        f1.close()
    sni_info[2] = snil
    return sni_info


def snie_get_tls_proto_info(packet, sni_info):
    from pyshark.packet.fields import LayerField
    tls_extension_version = "0x0a"
    tls_version = "0x0a"
    if int(packet['tcp'].dstport) == 443 or int(packet['tcp'].srcport) == 443:  # Encrypted TCP packet
        if 'tls' in packet:
            for layer in packet:
                if layer.layer_name == "tls":
                    llayer = dir(layer)
                    if "handshake_extensions_supported_version" in llayer:
                        tls_extension_version = layer.handshake_extensions_supported_version
                    if "record_version" in llayer:
                        tls_version = layer.record_version
                    if 'handshake_extensions_server_name' in llayer:
                        sni = layer.handshake_extensions_server_name.showname.replace("Server Name: ", "")
                        sni_info[2] = sni
                    final_version = max(int(str(tls_extension_version),16),int(str(tls_version),16))
                    if final_version != 0x0a:
                        final_version = str(hex(final_version))
                        final_version = f"{final_version[:2]}0{final_version[2:]}"
                        sni_info[1] = final_version

    return sni_info

def snie_update_tls_info(row, sni_info):
    if "NA" != sni_info[1]:
        row["TLS version"].add(sni_info[1])
    
    for sni in sni_info[2]:
        if "NA" in row["SNI"]:
            row["SNI"] = str(sni)
        else:
            if sni != "NA":
                row["SNI"] += " , " + str(sni)

    return row


def snie_handle_tcp(packet):
    if not 'tcp' in packet:
        return
    
    if generate_tcp_dict_key(packet) in processed_data.keys():
        row = generate_row_dict(processed_data[generate_tcp_dict_key(packet)])
        osize = int(row["Downloaded Data size (bytes)"])
        psize = snie_get_tcppayloadlen(packet)
        dsize = osize + psize
        row['Downloaded Data size (bytes)'] = dsize
        # Update TLS duration
        ti = float(row['Time'])
        te = float(packet.sniff_timestamp)
        tdiff = te - ti

        row["TLS session duration (s)"] = tdiff
        # Update TLS duration
        sni_info = ["NA", "NA", ["NA"]]
        sni_info = snie_get_tls_proto_info(packet, sni_info)
        row = snie_update_tls_info(row, sni_info)
        processed_data[generate_tcp_dict_key(packet)] = generate_list_from_dict(row)
    else:
        sni_info = snie_get_tcp_prot_info(packet)
        sni_info = snie_get_tls_proto_info(packet, sni_info)
        sni_info[1] = set([sni_info[1]])
        processed_data[generate_tcp_dict_key(packet)] = sni_info

def snie_get_proto_info(sni_info, packet):
    sni_info.append(str(packet['ip'].src))
    sni_info.append(str(packet['ip'].dst))
    sni_info.append(str(packet['tcp'].sport))
    sni_info.append(str(packet['tcp'].dport))
    sni_info.append(snie_get_tr_proto(packet['ip'].proto))
    sni_info.append(snie_get_tcppayloadlen(packet))
    sni_info.append(str(0))
    sni_info.append(str(0))
    sni_info.append(str(0))
    return sni_info


def snie_update_ch_info(fp, tls_msg, packet):
    # print("ClientHello message detected")
    sni_info = []
    sni_info.append(str(packet.time))
    ver = TLS_VERSIONS.get(tls_msg.version, "NA")
    sni_info.append(ver)
    for sniinfo in tls_msg['TLS_Ext_ServerName'].servernames:
        sni = ""
        # print("SNI Info per packet ")
        if True: #ver != "TLS_1_3":
            sni = sniinfo.servername.decode('utf-8')
            output_data = str(sni) + "\n"
            fp.write(output_data)
        fe = open("./Output_data/e.txt", "a")
        fe.write("SNI added " + str(sni))
        fe.close()
        f1 = open('./Output_data/snie_temp.csv', 'a', newline='')
        writer = csv.writer(f1)
        sni_info.append(str(sni))
        sni_info = snie_get_proto_info(sni_info, packet)
        writer.writerow(sni_info)
        f1.close()


def snie_update_cert_info(fp, tls_msg, packet):
    cert = "NA"
    print("Certificate message detected")
    clen = tls_msg.certslen
    print("Certificate length = " + str(clen))
    for cert in tls_msg.certs:
        print(cert)


def snie_handle_tcp_packet(fp, packet):
    if packet['tcp'].dport == 443 or packet['tcp'].sport == 443:  # Encrypted TCP packet
        if packet.haslayer('TLS'):
            tlsx = packet['TLS']
            if isinstance(tlsx, bytes):
                return packet
            tlsxtype = tlsx.type
            if tlsxtype == 22:  # TLS Handshake
                for tls_msg in tlsx.msg:
                    if isinstance(tls_msg, bytes):
                        continue
                    try:
                        if tls_msg.msgtype is not None and tls_msg.msgtype == 1:  # Client Hello
                            snie_update_ch_info(fp, tls_msg, packet)
                            snie_update_datasize(packet)
                        elif tls_msg.msgtype == 11:  # Certificate
                            snie_update_cert_info(fp, tls_msg, packet)
                    except AttributeError:
                        pass
            # else:
            #    print("Unsupported TLS message : " + str(tlsxtype))
    return packet


def snie_record_quic_info(saddr, daddr, sport, dport, sni, len, tstamp, tls_version):
    if generate_quic_dict_key(saddr, daddr, sport, dport) in processed_data.keys():
        row = generate_row_dict(processed_data[generate_quic_dict_key(saddr, daddr, sport, dport)])
        osize = int(row["Downloaded Data size (bytes)"])
        psize = len*8
        dsize = osize + psize
        row['Downloaded Data size (bytes)'] = str(dsize)
        # Update data size
        # Update TLS duration
        ti = float(row['Time'])
        te = float(tstamp)
        tdiff = te - ti
        # tdiff = tdiff.total_seconds()
        row["TLS session duration (s)"] = tdiff
        processed_data[generate_quic_dict_key(saddr, daddr, sport, dport)] = generate_list_from_dict(row)
    else:
        sni_info = snie_get_quic_prot_info(saddr, daddr, sport, dport, sni, len*8, tstamp, tls_version)
        processed_data[generate_quic_dict_key(saddr, daddr, sport, dport)] = sni_info


def snie_process_raw_packets(raw_pkts, MAX_PKT_COUNT):
    sd_pkts = []

    pkt_count = 0
    global tcp_count
    global udp_count
    global quic_count
    # Filter TLS packets nd get SNI
    for packet in raw_pkts:
        if 'ip' in packet:
            try:
                if 'quic' in packet:  # QUIC packet
                    from snie_quic import sne_quic_extract_pkt_info
                    saddr, daddr, sport, dport, sni, qlen, tstamp, tls_version = sne_quic_extract_pkt_info(packet)
                    snie_record_quic_info(saddr, daddr, sport, dport, sni, qlen, tstamp, tls_version)
                    quic_count += 1
                elif 'tcp' in packet:
                    x = snie_handle_tcp(packet)
                    tcp_count += 1
                elif 'udp' in packet:  # UDP packet
                    x = snie_handle_udp_packet(packet)
                    udp_count += 1
                else:
                    x = snie_handle_other_packet(packet)
            except KeyboardInterrupt:
                print("Execution interrupted")
                exit(0)
            pkt_count += 1
            print("[+] Number of packets processed : TCP = " + str(tcp_count) + "  UDP = " + str(udp_count) + \
                  "  QUIC = " + str(quic_count) + "  Total = " + str(pkt_count), end = "\r")
        if MAX_PKT_COUNT != "NA" and pkt_count >= MAX_PKT_COUNT:
            break

    # print("\nTCP : " + str(tcp_count) + "  UDP : " + str(udp_count) + "\n")
    return sd_pkts


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


def write_to_csv(data_list, fname):
    print("[+] Writing to csv file")
    with open(fname, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(header_index.keys())
        for line in data_list:
            if line == []:
                continue
            writer.writerow(line)


def get_flow_id(protocol, ip_src, ip_dst, port_src, port_dst):
    global flow_itr

    if protocol not in ["TCP", "UDP", "QUIC"]:
        return "NA"
    if ip_src > ip_dst:
        ip_src, ip_dst = ip_dst, ip_src
    
    if port_src > port_dst:
        port_src, port_dst = port_dst, port_src

    flow_id = flow_map.get((protocol, ip_src, ip_dst, port_src, port_dst), None)

    if(flow_id):
        return flow_id
    
    flow_id = flow_itr
    flow_map[(protocol, ip_src, ip_dst, port_src, port_dst)] = flow_id

    flow_itr += 1

    return flow_id

def add_flow_id(data_list):
    for line in data_list:
        if line == []:
            continue
        line.append(get_flow_id(line[header_index["Protocol"]], line[header_index["Source IP address"]], line[header_index["Destination IP address"]], line[header_index["Source port"]], line[header_index["Destination Port"]]))


def snie_process_packets(MAX_PKT_COUNT, STO, fname):

    # Just for making sure we have permission
    f1 = open('./Output_data/sni.csv', 'w', newline='')
    f1.close()
    
    itr = 1
    while itr == 1:
        itr += 1
        raw_pkts = snie_read_raw_pkts(STO, fname)
        if raw_pkts is None:
            print("Too few packets to sniff")
            break
        try:
            snie_process_raw_packets(raw_pkts, MAX_PKT_COUNT)
        except (KeyboardInterrupt, SystemExit):
            break
    processed_data_list = []

    for key in processed_data:
        processed_data_list.append(processed_data[key])       

    # pprint(processed_data)
    snie_sanitize_data_list(processed_data_list)
    add_flow_id(processed_data_list)

    write_to_csv(processed_data_list, './Output_data/sni.csv')
    return

def get_flow_id(protocol, ip_src, ip_dst, port_src, port_dst):
    global flow_itr

    if protocol not in ["TCP", "UDP", "QUIC"]:
        return "NA"
    if ip_src > ip_dst:
        ip_src, ip_dst = ip_dst, ip_src
    
    if port_src > port_dst:
        port_src, port_dst = port_dst, port_src

    flow_id = flow_map.get((protocol, ip_src, ip_dst, port_src, port_dst), None)

    if(flow_id):
        return flow_id
    
    flow_id = flow_itr
    flow_map[(protocol, ip_src, ip_dst, port_src, port_dst)] = flow_id

    flow_itr += 1

    return flow_id

def add_flow_id(data_list):
    header_index["Flow ID"] = len(header_index)
    for line in data_list:
        if line == []:
            continue
        line.append(get_flow_id(line[header_index["Protocol"]], line[header_index["Source IP address"]], line[header_index["Destination IP address"]], line[header_index["Source port"]], line[header_index["Destination Port"]]))

def snie_record_and_process_pkts(command, fname, STO=30):
    global itime
    MAX_PKT_COUNT = "NA" # "NA : no bound"
    if fname != None:
        snie_process_packets(MAX_PKT_COUNT, STO, fname)
    elif command == "ALL":
        snie_sniff_packets(STO)
        snie_process_packets(MAX_PKT_COUNT, STO)
    else:
      print("Unknown command : Use S/A/ALL")
