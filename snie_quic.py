
def sne_quic_extract_pkt_info(packet):
    llayer = dir(packet['quic'])
    # print("QUIC layer info : " + str(llayer))
    sni = 'NA'
    tls_version = 'NA'
    qlen = int(packet['quic'].packet_length)
    tstamp = float(packet.sniff_timestamp)
    if 'ip' in packet:
        saddr = packet['ip'].src
        daddr = packet['ip'].dst
    else:
        saddr = daddr = 0
    if 'udp' in packet:
        sport = packet['udp'].srcport
        dport = packet['udp'].dstport
    else:
        sport = dport = 0

    # print("QUIC packet : " + str(dir(packet['quic'])))
    if "tls_handshake_version" in llayer:
        tls_version = packet['quic'].tls_handshake_version
    if 'tls_handshake_extensions_server_name' in llayer:
        sni = packet['quic'].tls_handshake_extensions_server_name
    # else:
    #    print("SNI not present")
    # print("QUIC SNI = " + str(sni))
    return saddr, daddr, sport, dport, sni, qlen, tstamp, tls_version


def snie_quic(pcap_file, lfile):
    import pyshark

    pcap_data = pyshark.FileCapture(pcap_file)
    fp = open(lfile, "w")
    fp.close()

    pcount = 0
    quic_pinfo = []
    for packet in pcap_data:
        for layer in packet:
            if layer.layer_name == 'quic':
                fp = open(lfile, "a")
                saddr, daddr, sport, dport, sni = sne_quic_extract_pkt_info(packet, layer)
                quic_pinfo.append([saddr, daddr, sport, dport, sni])
                print("Extracted values : " + str(quic_pinfo))
                output_data = "QUIC packet detected : " + str(layer)
                #print(output_data)
                fp.write(str(packet))
                fp.write("\n END OF PACKET \n")
                fp.close()
                break
        pcount += 1
        print("Packets processed = ", str(pcount), end="\r")


if __name__ == '__main__':
    pcap_file = './Output_data/yt_quic.pcap'
    lfile = "./Output_data/plog.txt"
    snie_quic(pcap_file, lfile)