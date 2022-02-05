# -*- coding: utf-8 -*-
"""
@author: khandkar
"""
__spec__ = None

from snie_pkt_sniff import snie_record_and_process_pkts
import os
os.environ['MPLCONFIGDIR'] = "./mplotlibtemp"


def snie_main ():
    fp = open('Output_data/results', 'w')
    fp.close()
    fe = open("output_data/e.txt","w")
    fe.close()
    output_data = str("Sniffer Output") + ' :' + '\n'
    output_data += snie_record_and_process_pkts() + '\n'
    fp = open('Output_data/results', 'a')
    fp.write(output_data)
    fp.close()
    return output_data


if __name__ == '__main__':
    snie_main()