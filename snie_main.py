# -*- coding: utf-8 -*-
"""
@author: khandkar, hari hara sudhan
"""
__spec__ = None

from snie_pkt_sniff import snie_record_and_process_pkts
import os
os.environ['MPLCONFIGDIR'] = "./mplotlibtemp"

import sys


def snie_main (command, fname):
    print("[+] Initialising environment")
    if not os.path.exists("./Output_data"):
        os.system('mkdir Output_data')

    output_data = snie_record_and_process_pkts(command, fname)
    return output_data


if __name__ == '__main__':
    n = len(sys.argv)
    if(n > 1):
        fileName = sys.argv[1]
        command = "A"
        snie_main(command, fileName)
    else:
        command = "A"
        snie_main(command, None)