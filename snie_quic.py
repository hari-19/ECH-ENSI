
def sne_quic_extract_pkt_info(packet, layer):
    llayer = dir(layer)
    sni = 'NA'
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
    if 'tls_handshake_extensions_server_name_list_len' in llayer:
        # Assumes single SNI in the list
        if 'tls_handshake_extensions_server_name' in llayer:
            sni = layer.tls_handshake_extensions_server_name
    else:
        print("SNI not present")
    return saddr, daddr, sport, dport, sni


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