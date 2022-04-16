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

STO = 15 # Sniffing period in Seconds

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


def snie_read_raw_pkts(STO):
    fname = "./Input_data/pkts.pcap"
    print("[+] Reading packets from " + str(fname))
    pkts = pyshark.FileCapture(fname)
    print("[+] Reading done")
    return pkts


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
    "0xfefd": "DTLS_1_1"
    # Misc
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
    f2 = open('./Output_data/snie_temp.csv', 'a')
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
    os.system('cp ./Output_data/snie_temp.csv ./Output_data/snie.csv')
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


def snie_update_udp_data(dreader, packet):
    if not 'udp' in packet:
        return
    fe = open("./Output_data/e.txt", "a")
    f2 = open('./Output_data/snie_temp.csv', 'w')
    writer = csv.writer(f2)
    dwriter = csv.DictWriter(f2, fieldnames=csv_header)
    writer.writerow(csv_header)
    flow_id = str(packet['ip'].src) + "_" + str(packet['ip'].dst) + "_" + str(packet['udp'].srcport) + "_" \
              + str(packet['udp'].dstport)
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
        output_data = " P (UDP): " + str(packet['ip'].src) + ":" + str(packet['ip'].dst) + ":" + str(
            packet['udp'].srcport) + ":" + \
                      str(packet['udp'].dstport) + "\n"
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
        if ((str(packet['ip'].src) == row["Source IP address"] and
             str(packet['ip'].dst) == row["Destination IP address"]) ) and \
                ((str(packet['udp'].srcport) == row["Source port"] and
                  str(packet['udp'].dstport) == row["Destination Port"])):
            osize = int(row["Downloaded Data size (bytes)"])
            psize = snie_get_udppayloadlen(packet)
            dsize = osize + psize
            row['Downloaded Data size (bytes)'] = dsize
            # print("UDP Packet : " + str(row) + "\n")
            dwriter.writerow(row)
            fe.write("UDP packet updated\n")
            add_pkt = False
        else:
            dwriter.writerow(row)
    f1.close()
    if add_pkt:
        rcount += 1
        sni_info = snie_get_udp_prot_info(packet)
        # print("UDP Packet : " + str(sni_info) + "\n")
        writer.writerow(sni_info)
        fe = open("./Output_data/e.txt", "a")
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
    fe = open("./Output_data/e.txt", "a")
    fe.write("\n\n New UDP packet received \n ")
    fe.close()
    snie_update_udp_data(dreader, packet)
    return packet


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


def snie_update_other_data(dreader, packet):
    fe = open("./Output_data/e.txt", "a")
    f2 = open('./Output_data/snie_temp.csv', 'w')
    writer = csv.writer(f2)
    dwriter = csv.DictWriter(f2, fieldnames=csv_header)
    writer.writerow(csv_header)
    pcount = 0
    rcount = 0
    add_pkt = True
    f1 = open('./Output_data/snie.csv', 'r')
    reader = csv.reader(f1)
    dreader = csv.DictReader(f1, fieldnames=csv_header)
    for row in dreader:
        fe.write("Row :" + str(row) + "\n")
        rcount += 1
        output_data = " P (Other): " + str(packet['ip'].src) + ":" + str(packet['ip'].dst) \
                      #+ ":" + str(packet[UDP].sport) + ":" + str(packet[UDP].dport) + "\n"
        fe.write(output_data)
        output_data = " F (OTher): " + row["Source IP address"] + ":" + row["Destination IP address"] \
                      # + ":" + row["Source port"] + ":" + row["Destination Port"] + "\n"
        fe.write(output_data)
        if "Protocol" == str(row["Protocol"]):
            continue
        pcount += 1
        if ((str(packet['ip'].src) == row["Source IP address"] and
             str(packet['ip'].dst) == row["Destination IP address"]) and
            str(packet['ip'].proto == row["Protocol"])):
            #print("row " + str(row))
            osize = int(row["Downloaded Data size (bytes)"])
            psize = snie_get_otherpayloadlen(packet)
            dsize = osize + psize
            row['Downloaded Data size (bytes)'] = dsize
            dwriter.writerow(row)
            fe.write("UDP packet updated\n")
            add_pkt = False
        else:
            dwriter.writerow(row)
    f1.close()
    if add_pkt:
        rcount += 1
        sni_info = snie_get_other_prot_info(packet)
        writer.writerow(sni_info)
        fe = open("./Output_data/e.txt", "a")
        fe.write("New pkt info : " + str(sni_info) + "\n")
        fe.write("new Other packet added" + "\n")
    f2.close()
    os.system('cp ./Output_data/snie_temp.csv ./Output_data/snie.csv')
    fe.write("Number of rows : " + str(rcount) + "\n")
    fe.close()
    return add_pkt


def snie_handle_other_packet(fp, dreader, packet):
    from shutil import copy
    fe = open("./Output_data/e.txt", "a")
    fe.write("\n\n New other packet received \n ")
    fe.close()
    snie_update_other_data(dreader, packet)
    return packet


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
        f1 = open('./Output_data/snie_temp.csv', 'a')
        if snil[0] == "NA":
            snil[0] = str(sni)
        else:
            snil.append(str(sni))
        f1.close()
    sni_info[2] = snil
    return sni_info


def snie_get_tls_proto_info(fp, packet, sni_info):
    from pyshark.packet.fields import LayerField
    if int(packet['tcp'].dstport) == 443 or int(packet['tcp'].srcport) == 443:  # Encrypted TCP packet
        if 'tls' in packet:
            for layer in packet:
                if layer.layer_name == "tls":
                    llayer = dir(layer)
                    if "record_version" in llayer:
                        tls_version = layer.record_version
                        sni_info[1] = TLS_VERSIONS.get(tls_version, "NA")
                    if 'handshake_extensions_server_name' in llayer:
                        sni = layer.handshake_extensions_server_name.showname.replace("Server Name: ", "")
                        sni_info[2] = sni
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
    if not 'tcp' in packet:
        return
    fe = open("./Output_data/e.txt", "a")
    f2 = open('./Output_data/snie_temp.csv', 'w')
    writer = csv.writer(f2)
    dwriter = csv.DictWriter(f2, fieldnames=csv_header)
    writer.writerow(csv_header)
    flow_id = str(packet['ip'].src) + "_" + str(packet['ip'].dst) + "_" + str(packet['tcp'].srcport) + "_" \
              + str(packet['tcp'].dstport)
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
        output_data = " P (TCP): " + str(packet['ip'].src) + ":" + str(packet['ip'].dst) + ":" + str(
            packet['tcp'].srcport) + ":" + \
                      str(packet['tcp'].dstport) + "\n"
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
        if ((str(packet['ip'].src) == row["Source IP address"] and
             str(packet['ip'].dst) == row["Destination IP address"])) and \
                ((str(packet['tcp'].srcport) == row["Source port"] and
                  str(packet['tcp'].dstport) == row["Destination Port"])):
            osize = int(row["Downloaded Data size (bytes)"])
            psize = snie_get_tcppayloadlen(packet)
            dsize = osize + psize
            row['Downloaded Data size (bytes)'] = dsize
            # Update TLS duration
            ti = float(row['Time'])
            te = float(packet.sniff_timestamp)
            tdiff = te - ti
            # tdiff = tdiff.total_seconds()
            row["TLS session duration (s)"] = tdiff
            # Update TLS duration
            sni_info = ["NA", "NA", ["NA"]]
            sni_info = snie_get_tls_proto_info(fp, packet, sni_info)
            if sni_info[1] != "NA":
                row = snie_update_tls_info(row, sni_info)
            dwriter.writerow(row)
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
        fe = open("./Output_data/e.txt", "a")
        fe.write("New pkt info : " + str(sni_info) + "\n")
        fe.write("new TCP packet added" + "\n")
    f2.close()
    os.system('cp ./Output_data/snie_temp.csv ./Output_data/snie.csv')
    fe.write("Number of rows : " + str(rcount) + "\n")
    fe.close()
    return add_pkt


def snie_handle_tcp(fp, dreader, packet):
    from shutil import copy
    fe = open("./Output_data/e.txt", "a")
    fe.write("\n\n New TCP packet received \n ")
    fe.close()
    snie_update_tcp_data(fp, dreader, packet)
    return packet


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
                        # else:
                        # print("Unsupported TLS handshake message : " + str(tls_msg.msgtype))
                    except AttributeError:
                        pass
            # else:
            #    print("Unsupported TLS message : " + str(tlsxtype))
    return packet


def snie_record_quic_info(saddr, daddr, sport, dport, sni, len, tstamp, tls_version):
    fe = open("./Output_data/e.txt", "a")
    f2 = open('./Output_data/snie_temp.csv', 'w')
    writer = csv.writer(f2)
    dwriter = csv.DictWriter(f2, fieldnames=csv_header)
    writer.writerow(csv_header)
    flow_id = str(saddr) + "_" + str(daddr) + "_" + str(sport) + "_" \
              + str(dport)
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
        output_data = " P (UDP): " + str(saddr) + ":" + str(daddr) + ":" + str(sport) + ":" + \
                      str(dport) + "\n"
        fe.write(output_data)
        output_data = " F (UDP): " + row["Source IP address"] + ":" + row["Destination IP address"] + ":" + \
                      row["Source port"] + ":" + row["Destination Port"] + "\n"
        fe.write(output_data)
        if "Protocol" == str(row["Protocol"]):
            continue
        if "QUIC" != str(row["Protocol"]):
            fe.write("Non-UDP row \n")
            dwriter.writerow(row)
            continue
        pcount += 1
        if ((str(saddr) == row["Source IP address"] and
             str(daddr) == row["Destination IP address"]) ) and \
                ((str(sport) == row["Source port"] and
                  str(dport) == row["Destination Port"])):
            # Update data size
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
            # Update TLS duration
            dwriter.writerow(row)
            fe.write("UDP packet updated\n")
            add_pkt = False
        else:
            dwriter.writerow(row)
    f1.close()
    if add_pkt:
        rcount += 1
        sni_info = snie_get_quic_prot_info(saddr, daddr, sport, dport, sni, len*8, tstamp, tls_version)
        # print("QUIC SNI Info : " + str(sni_info))
        writer.writerow(sni_info)
        fe = open("./Output_data/e.txt", "a")
        #print("new UDP packet added")
        fe.write("New pkt info : " + str(sni_info) + "\n")
        fe.write("new QUIC packet added" + "\n")
    f2.close()
    os.system('cp ./Output_data/snie_temp.csv ./Output_data/snie.csv')
    fe.write("Number of rows : " + str(rcount) + "\n")
    #print("Number of rows : " + str(rcount))
    fe.close()
    return add_pkt


def snie_process_raw_packets(reader, dreader, raw_pkts, MAX_PKT_COUNT):
    sd_pkts = []
    fp = open('./Output_data/sni.txt', 'a')
    pkt_count = 0
    global tcp_count
    global udp_count
    global quic_count
    # Filter TLS packets nd get SNI
    for packet in raw_pkts:
        if 'ip' in packet:
            try:
                if 'tcp' in packet:
                    x = snie_handle_tcp(fp, dreader, packet)
                    tcp_count += 1
                elif 'udp' in packet:  # UDP packet
                    x = snie_handle_udp_packet(fp, dreader, packet)
                    udp_count += 1
                if 'quic' in packet:  # QUIC packet
                    from snie_quic import sne_quic_extract_pkt_info
                    saddr, daddr, sport, dport, sni, qlen, tstamp, tls_version = sne_quic_extract_pkt_info(packet)
                    snie_record_quic_info(saddr, daddr, sport, dport, sni, qlen, tstamp, tls_version)
                    quic_count += 1
                else:
                    x = snie_handle_other_packet(fp, dreader, packet)
            except KeyboardInterrupt:
                print("Execution interrupted")
                exit(0)
            pkt_count += 1
            print("[+] Number of packets processed : TCP = " + str(tcp_count) + "  UDP = " + str(udp_count) + \
                  "  QUIC = " + str(quic_count) + "  Total = " + str(pkt_count), end="\r")
        if MAX_PKT_COUNT != "NA" and pkt_count >= MAX_PKT_COUNT:
            break
    fp.close()
    # print("\nTCP : " + str(tcp_count) + "  UDP : " + str(udp_count) + "\n")
    return sd_pkts


def snie_sanitize_data():
    #print("Sanitising data")
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
        if "apple" in line or "macos" in line:
            continue
        if line[2] != "NA":
            sni = line[2]
            sni = sni.replace(" ", "")
            snil = list(sni.replace(",", ""))
            sni = ""
            for item in snil:
                if item != ",":
                    sni += item
            line[2] = sni
            writer.writerow(line)
        else:
            writer.writerow(line)
    f1.close()
    f2.close()
    os.system('cp ./Output_data/snie_s.csv ./Output_data/snie.csv')


def snie_process_packets(MAX_PKT_COUNT, STO):
    # Process packets
    if not os.path.exists("./Output_data/sni.txt"):
        os.system('touch ./Output_data/sni.txt')
    fp = open('./Output_data/sni.txt', 'w')
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
    fe = open("./Output_data/e.txt", "w")
    fe.close()
    itr = 1
    sd_pkts = None
    while itr == 1:
        itr += 1
        raw_pkts = snie_read_raw_pkts(STO)
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
    MAX_PKT_COUNT = "NA" # "NA : no bound"
    is_ps_stop.clear()
    print("[+] Analyser started ")
    snie_process_packets(MAX_PKT_COUNT, STO)
    print("[+] Analyser finished ")
    print("[+] Analyser output stored in ./Output_data/snie.csv")
    #    if command == "S":
#        snie_sniff_packets(STO)
#    elif command == "A":
#        snie_process_packets(MAX_PKT_COUNT, STO)
#    elif command == "ALL":
#        snie_sniff_packets(STO)
#        snie_process_packets(MAX_PKT_COUNT, STO)
#    else:
#        print("Unknown command : Use S/A/ALL")
