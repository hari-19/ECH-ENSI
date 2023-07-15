
def sne_quic_extract_pkt_info(packet):
    tls_extension_version = '0x0a'
    tls_version = '0x0a'

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

    if "tls_handshake_extensions_supported_version" in llayer:
        tls_extension_version = packet['quic'].tls_handshake_extensions_supported_version
    if "tls_handshake_version" in llayer:
        tls_version = packet['quic'].tls_handshake_version
    if 'tls_handshake_extensions_server_name' in llayer:
        sni = packet['quic'].tls_handshake_extensions_server_name

    if tls_version != 'NA':
        final_version = max(int(str(tls_extension_version),16),int(str(tls_version),16))
        final_version = str(hex(final_version))
        final_version = f"{final_version[:2]}0{final_version[2:]}"
        tls_version = final_version

    return saddr, daddr, sport, dport, sni, qlen, tstamp, tls_version


