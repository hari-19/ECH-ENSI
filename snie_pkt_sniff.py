# -*- coding: utf-8 -*-
"""
@author: khandkar
"""
import os.path

from scapy.all import *

load_layer("tls")
from scapy.layers.inet import IP, TCP
import csv

pkt_count = 0
pkts = []

itime = time.time()
capture = sniff(count=1)
is_ps_stop = Event()
tcp_count = 0
udp_count = 0

header = ["Time", "TLS version", "SNI", "Source IP address", "Destination IP address", "Source port",
          "Destination Port", "Protocol", "Downloaded Data size (bytes)", "TLS session duration (s)",
          "Foreground/Background", "SSL Certificate information"]

csv_header = {"Time": "Time", "TLS version": "TLS version", "SNI": "SNI", "Source IP address": "Source IP address",
              "Destination IP address": "Destination IP address", "Source port": "Source port",
              "Destination Port": "Destination Port", "Protocol": "Protocol",
              "Downloaded Data size (bytes)": "Downloaded Data size (bytes)",
              "TLS session duration (s)": "TLS session duration (s)",
              "Foreground/Background": "Foreground/Background",
              "SSL Certificate information": "SSL Certificate information"}

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
        os.system('mkdir ./Input_data')
    fname = "./Input_data/pkts_" + str(STO) + ".pcap"
    if not os.path.exists(fname):
        comm = 'touch ' + fname
        os.system(comm)
    capture = sniff(stop_filter=is_ps_stop.is_set(), timeout=STO)
    wrpcap(fname, capture)


def snie_read_raw_pkts():
    fname = "./Input_data/pkts.pcap"
    print("Reading packets  ....")
    pkts = rdpcap(fname)
    # pkts = capture
    print("Reading done ....")
    return pkts


TLS_VERSIONS = {
    # SSL
    0x0002: "SSL_2_0",
    0x0300: "SSL_3_0",
    # TLS:
    0x0301: "TLS_1_0",
    0x0302: "TLS_1_1",
    0x0303: "TLS_1_2",
    0x0304: "TLS_1_3",
    # DTLS
    0x0100: "PROTOCOL_DTLS_1_0_OPENSSL_PRE_0_9_8f",
    0x7f10: "TLS_1_3_DRAFT_16",
    0x7f12: "TLS_1_3_DRAFT_18",
    0xfeff: "DTLS_1_0",
    0xfefd: "DTLS_1_1",
}


def snie_get_tr_proto(ip):
    import socket
    if ip == socket.IPPROTO_TCP:
        return "TCP"
    elif ip == socket.IPPROTO_UDP:
        return "UDP"
    else:
        return "UNKNOWN"


def snie_get_tcppayloadlen(packet):
    t_len = len(packet[TCP].payload)
    return t_len


def snie_get_udppayloadlen(packet):
    t_len = len(packet[UDP].payload)
    return t_len


def snie_update_datasize(packet):
    if not packet.haslayer('TCP'):
        return
    fe = open("output_data/e.txt", "a")
    f2 = open('./Output_data/snie_temp.csv', 'a')
    writer = csv.writer(f2)
    dwriter = csv.DictWriter(f2, fieldnames=csv_header)
    flow_id = str(packet[IP].src) + "_" + str(packet[IP].dst) + "_" + str(packet[TCP].sport) + "_" \
              + str(packet[TCP].dport)
    # print("Flow id : " + str(flow_id) + str(reader))
    f1 = open('./Output_data/snie.csv', 'r')
    reader = csv.reader(f1)
    dreader = csv.DictReader(f1, fieldnames=csv_header)
    for row in dreader:
        output_data = " P : " + str(packet[IP].src) + ":" + str(packet[IP].dst) + ":" + str(packet[TCP].sport) + ":" + \
                      str(packet[TCP].dport) + "\n"
        output_data += " F : " + row["Source IP address"] + ":" + row["Destination IP address"] + ":" + \
                       row["Source port"] + ":" + row["Destination Port"] + "\n"
        fe.write(output_data)
        if "Protocol" == row["Protocol"]:
            continue
        if "TCP" != str(row["Protocol"]):
            dwriter.writerow(row)
            continue
        if ((str(packet[IP].src) == row["Source IP address"] and
             str(packet[IP].dst) == row["Destination IP address"]) or
            (str(packet[IP].dst) == row["Source IP address"] and
             str(packet[IP].src) == row["Destination IP address"])) and \
                ((str(packet[TCP].sport) == row["Source port"] and
                  str(packet[TCP].dport) == row["Destination Port"]) or
                 (str(packet[TCP].dport) == row["Source port"] and
                  str(packet[TCP].sport) == row["Destination Port"])):
            osize = int(row["Downloaded Data size (bytes)"])
            ti = float(row['Time'])
            # print("I time : " + str(ti))
            # print("osize : " + str(osize))
            psize = snie_get_tcppayloadlen(packet)
            # print("psize = " + str(psize))
            dsize = osize + psize
            # print("new size " + str(dsize))
            row['Downloaded Data size (bytes)'] = dsize
            te = packet.time
            # print("E time : " + str(te))
            tdiff = te - ti
            # print("Diff = " + str(tdiff))
            # tdfif = tdiff.total_seconds()
            # print("DiffS = " + str(tdiff))
            row["TLS session duration (s)"] = tdiff
            dwriter.writerow(row)
        else:
            # print("Not Updated row : " + str(row))
            dwriter.writerow(row)
    f1.close()
    f2.close()
    os.system('cp ./Output_data/snie_temp.csv ./Output_data/snie.csv')
    fe.close()


def snie_get_udp_prot_info(packet):
    sni_info = []
    sni_info.append(str(packet.time))
    sni_info.append("NA")
    sni_info.append("NA")
    sni_info.append(str(packet[IP].src))
    sni_info.append(str(packet[IP].dst))
    sni_info.append(str(packet[UDP].sport))
    sni_info.append(str(packet[UDP].dport))
    sni_info.append(snie_get_tr_proto(packet[IP].proto))
    psize = snie_get_udppayloadlen(packet)
    sni_info.append(str(psize))
    sni_info.append("NA")
    sni_info.append(str(0))
    sni_info.append(str(0))
    return sni_info


def snie_update_udp_data(dreader, packet):
    if not packet.haslayer('UDP'):
        return
    fe = open("output_data/e.txt", "a")
    f2 = open('./Output_data/snie_temp.csv', 'w')
    writer = csv.writer(f2)
    dwriter = csv.DictWriter(f2, fieldnames=csv_header)
    writer.writerow(csv_header)
    flow_id = str(packet[IP].src) + "_" + str(packet[IP].dst) + "_" + str(packet[UDP].sport) + "_" \
              + str(packet[UDP].dport)
    # print("Flow id : " + str(flow_id) + str(reader))
    pcount = 0
    rcount = 0
    add_pkt = True
    f1 = open('./Output_data/snie.csv', 'r')
    reader = csv.reader(f1)
    dreader = csv.DictReader(f1, fieldnames=csv_header)
    for row in dreader:
        fe.write("Row :" + str(row) + "\n")
        rcount += 1
        output_data = " P (UDP): " + str(packet[IP].src) + ":" + str(packet[IP].dst) + ":" + str(
            packet[UDP].sport) + ":" + \
                      str(packet[UDP].dport) + "\n"
        fe.write(output_data)
        output_data = " F (UDP): " + row["Source IP address"] + ":" + row["Destination IP address"] + ":" + \
                      row["Source port"] + ":" + row["Destination Port"] + "\n"
        fe.write(output_data)
        if "Protocol" == str(row["Protocol"]):
            continue
        if "UDP" != str(row["Protocol"]):
            fe.write("Non-UDP row \n")
            dwriter.writerow(row)
            continue
        pcount += 1
        if ((str(packet[IP].src) == row["Source IP address"] and
             str(packet[IP].dst) == row["Destination IP address"]) or
            (str(packet[IP].dst) == row["Source IP address"] and
             str(packet[IP].src) == row["Destination IP address"])) and \
                ((str(packet[UDP].sport) == row["Source port"] and
                  str(packet[UDP].dport) == row["Destination Port"]) or
                 (str(packet[UDP].dport) == row["Source port"] and
                  str(packet[UDP].sport) == row["Destination Port"])):
            osize = int(row["Downloaded Data size (bytes)"])
            psize = snie_get_udppayloadlen(packet)
            dsize = osize + psize
            row['Downloaded Data size (bytes)'] = dsize
            dwriter.writerow(row)
            #print("UDP packet updated")
            fe.write("UDP packet updated\n")
            add_pkt = False
        else:
            dwriter.writerow(row)
    f1.close()
    if add_pkt:
        rcount += 1
        sni_info = snie_get_udp_prot_info(packet)
        writer.writerow(sni_info)
        fe = open("output_data/e.txt", "a")
        #print("new UDP packet added")
        fe.write("New pkt info : " + str(sni_info) + "\n")
        fe.write("new UDP packet added" + "\n")
    f2.close()
    os.system('cp ./Output_data/snie_temp.csv ./Output_data/snie.csv')
    fe.write("Number of rows : " + str(rcount) + "\n")
    #print("Number of rows : " + str(rcount))
    fe.close()
    return add_pkt


def snie_handle_udp_packet(fp, dreader, packet):
    from shutil import copy
    fe = open("output_data/e.txt", "a")
    fe.write("\n\n New UDP packet received \n ")
    fe.close()
    snie_update_udp_data(dreader, packet)
    return packet


def snie_get_tcp_prot_info(packet):
    sni_info = []
    sni_info.append(str(packet.time))
    sni_info.append("NA")
    sni_info.append("NA")
    sni_info.append(str(packet[IP].src))
    sni_info.append(str(packet[IP].dst))
    sni_info.append(str(packet[TCP].sport))
    sni_info.append(str(packet[TCP].dport))
    sni_info.append(snie_get_tr_proto(packet[IP].proto))
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
    ver = TLS_VERSIONS[tls_msg.version]
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
        fe = open("output_data/e.txt", "a")
        fe.write("SNI added " + str(sni))
        fe.close()
        f1 = open('./Output_data/snie_temp.csv', 'a')
        if snil[0] == "NA":
            snil[0] = str(sni)
        else:
            snil.append(str(sni))
        f1.close()
    sni_info[2] = snil
    return sni_info


def snie_get_tls_proto_info(fp, packet, sni_info):
    if packet[TCP].dport == 443 or packet[TCP].sport == 443:  # Encrypted TCP packet
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
                            sni_info = snie_fill_ch_info(fp, tls_msg, sni_info)
                        elif tls_msg.msgtype == 11:  # Certificate
                            snie_update_cert_info(fp, tls_msg, packet)
                        # else:
                        # print("Unsupported TLS handshake message : " + str(tls_msg.msgtype))
                    except AttributeError:
                        pass
            else:
                sni_info[1] = str(TLS_VERSIONS[tlsx.version])
    return sni_info


def snie_update_tls_info(row, sni_info):
    row["TLS version"] = sni_info[1]
    for sni in sni_info[2]:
        if "NA" in row["SNI"]:
            row["SNI"] = str(sni)
        else:
            if sni != "NA":
                row["SNI"] += " , " + str(sni)
    #row["SNI"] = sni_info[2]
    return row


def snie_update_tcp_data(fp, dreader, packet):
    if not packet.haslayer('TCP'):
        return
    fe = open("output_data/e.txt", "a")
    f2 = open('./Output_data/snie_temp.csv', 'w')
    writer = csv.writer(f2)
    dwriter = csv.DictWriter(f2, fieldnames=csv_header)
    writer.writerow(csv_header)
    flow_id = str(packet[IP].src) + "_" + str(packet[IP].dst) + "_" + str(packet[TCP].sport) + "_" \
              + str(packet[TCP].dport)
    # print("Flow id : " + str(flow_id) + str(reader))
    pcount = 0
    rcount = 0
    add_pkt = True
    f1 = open('./Output_data/snie.csv', 'r')
    reader = csv.reader(f1)
    dreader = csv.DictReader(f1, fieldnames=csv_header)
    for row in dreader:
        fe.write("Row :" + str(row) + "\n")
        rcount += 1
        output_data = " P (TCP): " + str(packet[IP].src) + ":" + str(packet[IP].dst) + ":" + str(
            packet[TCP].sport) + ":" + \
                      str(packet[TCP].dport) + "\n"
        fe.write(output_data)
        output_data = " F (TCP): " + row["Source IP address"] + ":" + row["Destination IP address"] + ":" + \
                      row["Source port"] + ":" + row["Destination Port"] + "\n"
        fe.write(output_data)
        if "Protocol" == str(row["Protocol"]):
            continue
        if "TCP" != str(row["Protocol"]):
            fe.write("Non-TCP row \n")
            dwriter.writerow(row)
            continue
        pcount += 1
        if ((str(packet[IP].src) == row["Source IP address"] and
             str(packet[IP].dst) == row["Destination IP address"]) or
            (str(packet[IP].dst) == row["Source IP address"] and
             str(packet[IP].src) == row["Destination IP address"])) and \
                ((str(packet[TCP].sport) == row["Source port"] and
                  str(packet[TCP].dport) == row["Destination Port"]) or
                 (str(packet[TCP].dport) == row["Source port"] and
                  str(packet[TCP].sport) == row["Destination Port"])):
            osize = int(row["Downloaded Data size (bytes)"])
            psize = snie_get_tcppayloadlen(packet)
            dsize = osize + psize
            row['Downloaded Data size (bytes)'] = dsize
            sni_info = ["NA", "NA", ["NA"]]
            sni_info = snie_get_tls_proto_info(fp, packet, sni_info)
            if sni_info[1] != "NA":
                row = snie_update_tls_info(row, sni_info)
            dwriter.writerow(row)
            #print("UDP packet updated")
            fe.write("TCP packet updated\n")
            add_pkt = False
        else:
            dwriter.writerow(row)
    f1.close()
    if add_pkt:
        rcount += 1
        sni_info = snie_get_tcp_prot_info(packet)
        sni_info = snie_get_tls_proto_info(fp, packet, sni_info)
        writer.writerow(sni_info)
        fe = open("output_data/e.txt", "a")
        fe.write("New pkt info : " + str(sni_info) + "\n")
        fe.write("new TCP packet added" + "\n")
    f2.close()
    os.system('cp ./Output_data/snie_temp.csv ./Output_data/snie.csv')
    fe.write("Number of rows : " + str(rcount) + "\n")
    fe.close()
    return add_pkt


def snie_handle_tcp(fp, dreader, packet):
    from shutil import copy
    fe = open("output_data/e.txt", "a")
    fe.write("\n\n New TCP packet received \n ")
    fe.close()
    snie_update_tcp_data(fp, dreader, packet)
    return packet


def snie_get_proto_info(sni_info, packet):
    sni_info.append(str(packet[IP].src))
    sni_info.append(str(packet[IP].dst))
    sni_info.append(str(packet[TCP].sport))
    sni_info.append(str(packet[TCP].dport))
    sni_info.append(snie_get_tr_proto(packet[IP].proto))
    sni_info.append(snie_get_tcppayloadlen(packet))
    sni_info.append(str(0))
    sni_info.append(str(0))
    sni_info.append(str(0))
    return sni_info


def snie_update_ch_info(fp, tls_msg, packet):
    # print("ClientHello message detected")
    sni_info = []
    sni_info.append(str(packet.time))
    ver = TLS_VERSIONS[tls_msg.version]
    sni_info.append(ver)
    for sniinfo in tls_msg['TLS_Ext_ServerName'].servernames:
        sni = ""
        # print("SNI Info per packet ")
        if True: #ver != "TLS_1_3":
            sni = sniinfo.servername.decode('utf-8')
            output_data = str(sni) + "\n"
            fp.write(output_data)
        fe = open("output_data/e.txt", "a")
        fe.write("SNI added " + str(sni))
        fe.close()
        f1 = open('./Output_data/snie_temp.csv', 'a')
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
    if packet[TCP].dport == 443 or packet[TCP].sport == 443:  # Encrypted TCP packet
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
                        # else:
                        # print("Unsupported TLS handshake message : " + str(tls_msg.msgtype))
                    except AttributeError:
                        pass
            # else:
            #    print("Unsupported TLS message : " + str(tlsxtype))
    return packet


def snie_process_raw_packets(reader, dreader, raw_pkts, MAX_PKT_COUNT):
    sd_pkts = []
    fp = open('output_data/sni.txt', 'a')
    pkt_count = 0
    global tcp_count
    global udp_count
    # Filter TLS packets nd get SNI
    sessions = raw_pkts.sessions()
    for session in sessions:
        for packet in sessions[session]:
            try:
                if packet.haslayer('IP'):
                    if packet[IP].proto == 6: # TCP packet
                        tcp_count += 1
                        #x = snie_handle_tcp_packet(fp, packet)
                        x = snie_handle_tcp(fp, dreader, packet)
                    elif packet[IP].proto == 17:  # UDP packet
                        udp_count += 1
                        x = snie_handle_udp_packet(fp, dreader, packet)
                    # else:
                    #    print("Unkown transport protocol")
            except KeyboardInterrupt:
                print("Execution interrupted")
                exit(0)
            pkt_count += 1
            print("Number of packets processed : " + str(pkt_count), end = "\r")
        if MAX_PKT_COUNT != "NA" and pkt_count >= MAX_PKT_COUNT:
            print("\nTCP : " + str(tcp_count) + "  UDP : " + str(udp_count) + "\n")
            break
    fp.close()
    return sd_pkts


def snie_sanitize_data():
    if os.path.exists('./Output_data/snie_s.csv'):
        os.system('rm -rf ./Output_data/snie_s.csv')
        os.system('touch ./Output_data/snie_s.csv')
    else:
        os.system('touch ./Output_data/snie_s.csv')
    f1 = open('./Output_data/snie_s.csv', 'w')
    writer = csv.writer(f1)
    f2 = open('./Output_data/snie.csv', 'r')
    reader = csv.reader(f2)
    for line in reader:
        if "apple" in line:
            print(str(line) + "\n")
        else:
            writer.writerow(line)
    f1.close()
    f2.close()




def snie_process_packets(MAX_PKT_COUNT):
    # Process packets
    if not os.path.exists("output_data/sni.txt"):
        os.system('touch output_data/sni.txt')
    fp = open('output_data/sni.txt', 'w')
    fp.close()
    # Open reader file
    if os.path.exists('./Output_data/snie.csv'):
        os.system('rm -rf ./Output_data/snie.csv')
        os.system('touch ./Output_data/snie.csv')
    else:
        os.system('touch ./Output_data/snie.csv')
    f1 = open('./Output_data/snie.csv', 'r')
    reader = csv.reader(f1)
    dreader = csv.DictReader(f1, fieldnames=csv_header)
    f1.close()
    dreader = None
    # Open writer file
    fe = open("output_data/e.txt", "w")
    fe.close()
    itr = 1
    sd_pkts = None
    while itr == 1:
        itr += 1
        raw_pkts = snie_read_raw_pkts()
        if raw_pkts is None:
            print("Too few packets to sniff")
            is_ps_stop.set()
            break
        if True:
            try:
                sd_pkts = snie_process_raw_packets(reader, dreader, raw_pkts, MAX_PKT_COUNT)
            except (KeyboardInterrupt, SystemExit):
                is_ps_stop.set()
                break
    snie_sanitize_data()
    return


def snie_record_and_process_pkts(command):
    global is_ps_stop
    global itime
    STO = 5 # Sniffing period in Seconds
    MAX_PKT_COUNT = "NA" # "NA : no bound"
    is_ps_stop.clear()
    if command == "S":
        snie_sniff_packets(STO)
    elif command == "A":
        snie_process_packets(MAX_PKT_COUNT)
    elif command == "ALL":
        snie_sniff_packets(STO)
        snie_process_packets(MAX_PKT_COUNT)
    else:
        print("Unknown command : Use S/A/ALL")
