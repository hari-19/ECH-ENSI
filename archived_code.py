# def snie_get_host():
#     import socket
#     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     s.connect(("8.8.8.8", 80))
#     host = s.getsockname()[0]
#     print(host)
#     return host


# TLS_VERSIONS = {
#     # SSL
#     "0x0002": "SSL_2_0",
#     "0x0300": "SSL_3_0",
#     # TLS:
#     "0x0301": "TLS_1_0",
#     "0x0302": "TLS_1_1",
#     "0x0303": "TLS_1_2",
#     "0x0304": "TLS_1_3",
#     # DTLS
#     "0x0100": "PROTOCOL_DTLS_1_0_OPENSSL_PRE_0_9_8f",
#     "0x7f10": "TLS_1_3_DRAFT_16",
#     "0x7f12": "TLS_1_3_DRAFT_18",
#     "0xfeff": "DTLS_1_0",
#     "0xfefd": "DTLS_1_1",
# }


# def snie_handle_tcp_packet(fp, packet):
#     if packet['tcp'].dport == 443 or packet['tcp'].sport == 443:  # Encrypted TCP packet
#         if packet.haslayer('TLS'):
#             tlsx = packet['TLS']
#             if isinstance(tlsx, bytes):
#                 return packet
#             tlsxtype = tlsx.type
#             if tlsxtype == 22:  # TLS Handshake
#                 for tls_msg in tlsx.msg:
#                     if isinstance(tls_msg, bytes):
#                         continue
#                     try:
#                         if tls_msg.msgtype is not None and tls_msg.msgtype == 1:  # Client Hello
#                             snie_update_ch_info(fp, tls_msg, packet)
#                             snie_update_datasize(packet)
#                         elif tls_msg.msgtype == 11:  # Certificate
#                             snie_update_cert_info(fp, tls_msg, packet)
#                     except AttributeError:
#                         pass
#             # else:
#             #    print("Unsupported TLS message : " + str(tlsxtype))
#     return packet


# def snie_update_datasize(packet):
#     if not packet.haslayer('TCP'):
#         return
#     fe = open("./Output_data/e.txt", "a")
#     f2 = open('./Output_data/snie_temp.csv', 'a', newline='')
#     writer = csv.writer(f2)
#     dwriter = csv.DictWriter(f2, fieldnames=csv_header)
#     flow_id = str(packet['ip'].src) + "_" + str(packet['ip'].dst) + "_" + str(packet['tcp'].sport) + "_" \
#               + str(packet['tcp'].dport)
#     # print("Flow id : " + str(flow_id) + str(reader))
#     f1 = open('./Output_data/snie.csv', 'r')
#     reader = csv.reader(f1)
#     dreader = csv.DictReader(f1, fieldnames=csv_header)
#     for row in dreader:
#         output_data = " P : " + str(packet['ip'].src) + ":" + str(packet['ip'].dst) + ":" + str(packet['tcp'].sport) + ":" + \
#                       str(packet['tcp'].dport) + "\n"
#         output_data += " F : " + row["Source IP address"] + ":" + row["Destination IP address"] + ":" + \
#                        row["Source port"] + ":" + row["Destination Port"] + "\n"
#         fe.write(output_data)
#         if "Protocol" == row["Protocol"]:
#             continue
#         if "TCP" != str(row["Protocol"]):
#             dwriter.writerow(row)
#             continue
#         if ((str(packet['ip'].src) == row["Source IP address"] and
#              str(packet['ip'].dst) == row["Destination IP address"]) ) and \
#                 ((str(packet['tcp'].sport) == row["Source port"] and
#                   str(packet['tcp'].dport) == row["Destination Port"])):
#             osize = int(row["Downloaded Data size (bytes)"])
#             ti = float(row['Time'])
#             # print("I time : " + str(ti))
#             # print("osize : " + str(osize))
#             psize = snie_get_tcppayloadlen(packet)
#             # print("psize = " + str(psize))
#             dsize = osize + psize
#             # print("new size " + str(dsize))
#             row['Downloaded Data size (bytes)'] = dsize
#             te = packet.sniff_timestamp
#             # print("E time : " + str(te))
#             tdiff = te - ti
#             # print("Diff = " + str(tdiff))
#             tdiff = tdiff.total_seconds()
#             # print("DiffS = " + str(tdiff))
#             row["TLS session duration (s)"] = tdiff
#             dwriter.writerow(row)
#         else:
#             # print("Not Updated row : " + str(row))
#             dwriter.writerow(row)
#     f1.close()
#     f2.close()
#     os.chdir('Output_data')
#     os.system('del snie.csv')
#     os.system('ren snie_temp.csv snie.csv')
#     os.chdir('..')

#     fe.close()


# def snie_fill_cert_info(tls_msg):
#     cert = "NA"
#     print("Certificate message detected")
#     clen = tls_msg.certslen
#     print("Certificate length = " + str(clen))
#     for cert in tls_msg.certs:
#         print(cert)


# def snie_fill_ch_info(fp, tls_msg, sni_info):
#     #print("Printing TLS SNI info" + "\n")
#     #print(tls_msg)
#     #exit(0)

#     ver = tls_msg.version
#     sni_info[1] = str(ver)
#     snil = ["NA"]
#     for sniinfo in tls_msg['TLS_Ext_ServerName'].servernames:
#         sni = ""
#         #print("SNI Info per packet " + str(ver) + "\n")
#         if True: #ver != "TLS_1_3":
#             sni = sniinfo.servername.decode('utf-8')
#             output_data = str(sni) + "\n"
#             fp.write(output_data)
#             #print(output_data + "\n")
#         fe = open("./Output_data/e.txt", "a")
#         fe.write("SNI added " + str(sni))
#         fe.close()
#         f1 = open('./Output_data/snie_temp.csv', 'a', newline='')
#         if snil[0] == "NA":
#             snil[0] = str(sni)
#         else:
#             snil.append(str(sni))
#         f1.close()
#     sni_info[2] = snil
#     return sni_info


# def snie_get_proto_info(sni_info, packet):
#     sni_info.append(str(packet['ip'].src))
#     sni_info.append(str(packet['ip'].dst))
#     sni_info.append(str(packet['tcp'].sport))
#     sni_info.append(str(packet['tcp'].dport))
#     sni_info.append(snie_get_tr_proto(packet['ip'].proto))
#     sni_info.append(snie_get_tcppayloadlen(packet))
#     sni_info.append(str(0))
#     sni_info.append(str(0))
#     sni_info.append(str(0))
#     return sni_info


# def snie_update_ch_info(fp, tls_msg, packet):
#     # print("ClientHello message detected")
#     sni_info = []
#     sni_info.append(str(packet.time))
#     ver = tls_msg.version
#     sni_info.append(ver)
#     for sniinfo in tls_msg['TLS_Ext_ServerName'].servernames:
#         sni = ""
#         # print("SNI Info per packet ")
#         if True: #ver != "TLS_1_3":
#             sni = sniinfo.servername.decode('utf-8')
#             output_data = str(sni) + "\n"
#             fp.write(output_data)
#         fe = open("./Output_data/e.txt", "a")
#         fe.write("SNI added " + str(sni))
#         fe.close()
#         f1 = open('./Output_data/snie_temp.csv', 'a', newline='')
#         writer = csv.writer(f1)
#         sni_info.append(str(sni))
#         sni_info = snie_get_proto_info(sni_info, packet)
#         writer.writerow(sni_info)
#         f1.close()


# def snie_update_cert_info(fp, tls_msg, packet):
#     cert = "NA"
#     print("Certificate message detected")
#     clen = tls_msg.certslen
#     print("Certificate length = " + str(clen))
#     for cert in tls_msg.certs:
#         print(cert)


# def snie_handle_tcp_packet(fp, packet):
#     if packet['tcp'].dport == 443 or packet['tcp'].sport == 443:  # Encrypted TCP packet
#         if packet.haslayer('TLS'):
#             tlsx = packet['TLS']
#             if isinstance(tlsx, bytes):
#                 return packet
#             tlsxtype = tlsx.type
#             if tlsxtype == 22:  # TLS Handshake
#                 for tls_msg in tlsx.msg:
#                     if isinstance(tls_msg, bytes):
#                         continue
#                     try:
#                         if tls_msg.msgtype is not None and tls_msg.msgtype == 1:  # Client Hello
#                             snie_update_ch_info(fp, tls_msg, packet)
#                             snie_update_datasize(packet)
#                         elif tls_msg.msgtype == 11:  # Certificate
#                             snie_update_cert_info(fp, tls_msg, packet)
#                     except AttributeError:
#                         pass
#             # else:
#             #    print("Unsupported TLS message : " + str(tlsxtype))
#     return packet


