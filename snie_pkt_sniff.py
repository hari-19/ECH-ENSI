# -*- coding: utf-8 -*-
"""
@author: khandkar
"""

from scapy.all import *
load_layer("tls")
from scapy.layers.inet import IP, TCP
import csv

pkt_count = 0
pkts = []

capture = sniff(count=1)
is_ps_stop: bool = False
csv_header = ["Time","TLS version","SNI","Source IP address","Destination IP address","Source port",
              "Destination Port","Protocol","Downloaded Data size (bytes)","TLS session duration (s)",
              "Foreground/Background","SSL Certificate information"]


data_size = {}


def snie_get_host():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    host = s.getsockname()[0]
    print(host)
    return host


def snie_sniff_packets():
    global capture
    print("Packet sniffer started...")
    #fname = "./Input_data/pkts.pcap"
    while True:
        capture = sniff(count=2000, stop_filter=lambda x: is_ps_stop)


def snie_read_raw_pkts():
    pkts = []
    # fname = "./Input_data/pkts.pcap"
    #print("Reading packets  ....")
    #pkts = rdpcap(fname)
    pkts = capture
    #print("Reading done ....")
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
    else:
        return "UNKNOWN"


def snie_get_tcppayloadlen(packet):
    t_len = len(packet[TCP].payload)
    return t_len


def snie_update_datasize(packet):
    fe = open("output_data/e.txt","a")
    f = open('output_data/snie.csv', 'r')
    reader = csv.DictReader(f, fieldnames=csv_header)
    f1 = open('output_data/snie1.csv', 'w')
    writer = csv.DictWriter(f1, fieldnames=csv_header)
    flow_id = str(packet[IP].src) + "_" + str(packet[IP].dst) + "_" + str(packet[TCP].sport) + "_" \
              + str(packet[TCP].dport)
    # print("Flow id : " + str(flow_id) + str(reader))
    for row in reader:
        output_data = " P : " + str(packet[IP].src) + ":" + str(packet[IP].dst) + ":" + str(packet[TCP].sport) + ":" +\
              str(packet[TCP].dport) + "\n"
        output_data += " F : " + row["Source IP address"] + ":" + row["Destination IP address"] + ":" + \
            row["Source port"] + ":" + row["Destination Port"] + "\n"
        fe.write(output_data)
        if ((str(packet[IP].src) in row["Source IP address"] and
                str(packet[IP].dst) in row["Destination IP address"]) or
                (str(packet[IP].dst) in row["Source IP address"] and
                str(packet[IP].src) in row["Destination IP address"])) and \
                ((str(packet[TCP].sport) in row["Source port"] and
                str(packet[TCP].dport) in row["Destination Port"]) or
                (str(packet[TCP].dport) in row["Source port"] and
                str(packet[TCP].sport) in row["Destination Port"])):
            osize = int(row["Downloaded Data size (bytes)"])
            ti = float(row['Time'])
            #print("I time : " + str(ti))
            #print("osize : " + str(osize))
            psize = snie_get_tcppayloadlen(packet)
            #print("psize = " + str(psize))
            dsize = osize + psize
            #print("new size " + str(dsize))
            row['Downloaded Data size (bytes)'] = dsize
            te = packet.time
            #print("E time : " + str(te))
            tdiff = te - ti
            #print("Diff = " + str(tdiff))
            #tdfif = tdiff.total_seconds()
            #print("DiffS = " + str(tdiff))
            row["TLS session duration (s)"] = tdiff
            writer.writerow(row)
        else:
            # print("Not Updated row : " + str(row))
            writer.writerow(row)
    f.close()
    f1.close()
    fe.close()
    os.remove('output_data/snie.csv')
    os.rename('output_data/snie1.csv', 'output_data/snie.csv')


def snie_get_proto_info(sni_info, packet):
    sni_info.append(str(packet[IP].src))
    sni_info.append(str(packet[IP].dst))
    sni_info.append(str(packet[TCP].sport))
    sni_info.append(str(packet[TCP].dport))
    sni_info.append(snie_get_tr_proto(packet[IP].proto))
    sni_info.append(snie_get_tcppayloadlen(packet))
    sni_info.append(str(0))
    return sni_info


def snie_update_ch_info(fp, tls_msg, packet):
    print("ClientHello message detected")
    sni_info = []
    sni_info.append(str(packet.time))
    ver = TLS_VERSIONS[tls_msg.version]
    sni_info.append(ver)
    for sniinfo in tls_msg['TLS_Ext_ServerName'].servernames:
        # print("SNI Info per packet ")
        if ver != "TLS_1_3":
            sni = sniinfo.servername.decode('utf-8')
            output_data = str(sni) + "\n"
            fp.write(output_data)
        else:
            sni = ""
        fpcsv = open('output_data/snie.csv', 'a')
        writer = csv.writer(fpcsv)
        sni_info.append(str(sni))
        sni_info = snie_get_proto_info(sni_info, packet)
        writer.writerow(sni_info)
        fpcsv.close()


def snie_update_cert_info(fp, tls_msg, packet):
    cert = "NA"
    print("Certificate message detected")
    clen = tls_msg.certslen
    print("Certificate length = " + str(clen))
    for cert in tls_msg.certs:
        print(cert)


def snie_process_raw_packets(host, raw_pkts):
    import socket
    from scapy.layers.tls.basefields import _tls_version, _TLSClientVersionField
    sd_pkts = []
    fp = open('output_data/sni.txt', 'a')
    pkt_count = 0
    # Filter TLS packets nd get SNI
    sessions = raw_pkts.sessions()
    for session in sessions:
        for packet in sessions[session]:
            try:
                if packet.haslayer('IP') and packet[IP].proto == 6: # TCP packet
                    if packet[TCP].dport == 443 or packet[TCP].sport == 443: # Encrypted TCP packet
                        if packet.haslayer('TLS'):
                            tlsx = packet['TLS']
                            tlsxtype = tlsx.type
                            if tlsxtype == 22: # TLS Handshake
                                for tls_msg in tlsx.msg:
                                    if tls_msg.msgtype == 1: # Client Hello
                                        snie_update_ch_info(fp, tls_msg, packet)
                                    elif tls_msg.msgtype == 11: # Certificate
                                         snie_update_cert_info(fp, tls_msg, packet)
                                    else:
                                        print("Unsupported TLS handshake message : " + str(tls_msg.msgtype))
                            #else:
                            #    print("Unsupported TLS message : " + str(tlsxtype))
                    snie_update_datasize(packet)
            except KeyboardInterrupt:
                print("Execution interrupted")
                exit(0)
            pkt_count += 1
    fp.close()
    return sd_pkts


def snie_record_and_process_pkts():
    sd_pkts = []
    global is_ps_stop
    host = snie_get_host()
    # Record pkts
    ps = threading.Thread(target=snie_sniff_packets,
                              args=())
    ps.start()
    # Process packets
    fp = open('output_data/sni.txt', 'w')
    fp.close()
    fpcsv = open('output_data/snie.csv', 'w')
    # create the csv writer
    writer = csv.writer(fpcsv)
    writer.writerow(csv_header)
    fpcsv.close()
    while True:
        raw_pkts = snie_read_raw_pkts()
        if raw_pkts is None:
            print("Too few packets to sniff")
            is_ps_stop = True
            break
        else:
            try:
                sd_pkts = snie_process_raw_packets(host, raw_pkts)
            except (KeyboardInterrupt, SystemExit):
                is_ps_stop = True
                break
    output_data = "SNI =" + str(sd_pkts)
    print(output_data)
    return output_data
