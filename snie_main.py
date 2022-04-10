# -*- coding: utf-8 -*-
"""
@author: khandkar
"""
__spec__ = None

from snie_pkt_sniff import snie_record_and_process_pkts
import os
os.environ['MPLCONFIGDIR'] = "./mplotlibtemp"


def snie_main (command):
    if not os.path.exists("./Output_data"):
        os.system('mkdir Output_data')
    if not os.path.exists("Output_data/results"):
        os.system('touch Output_data/results')
    fp = open('Output_data/results', 'w')
    fp.close()
    if not os.path.exists("Output_data/e.txt"):
        os.system('touch Output_data/e.txt')
    fe = open("Output_data/e.txt","w")
    fe.close()
    output_data = snie_record_and_process_pkts(command)
    return output_data


if __name__ == '__main__':
    import sys
    alen = len(sys.argv)
    if 2 != alen:
        print("Usage : python snie_main.py <S/P/ALL>")
        sys.exit()
    else:
        command = sys.argv[1]
    snie_main(command)