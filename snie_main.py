# -*- coding: utf-8 -*-
"""
@author: khandkar, hari hara sudhan
"""
__spec__ = None

from snie_pkt_sniff import snie_process_packets, snie_sniff_packets, snie_sniff_and_analyse_packets
import os
import argparse, sys
os.environ['MPLCONFIGDIR'] = "./mplotlibtemp"


# def snie_main (command, fname):
#     print("[+] Initialising environment")
#     if not os.path.exists("./Output_data"):
#         os.system('mkdir Output_data')

#     output_data = snie_record_and_process_pkts(command, fname)
#     return output_data


if __name__ == '__main__':
    parser=argparse.ArgumentParser()

    parser.add_argument("-c", "--command", help="a for analyse, s for sniff, b for both")
    parser.add_argument("-sf", "--snifffile", help="File to analyse/ file to save sniffed data")
    parser.add_argument("-of", "--outputfile", help="Filename to save the output")
    parser.add_argument("-t", "--time", help="Time in seconds to sniff")

    args=parser.parse_args()

    print("[+] Initialising environment")
    if not os.path.exists("./Output_data"):
        os.system('mkdir Output_data')
    
    if not os.path.exists("./Input_data"):
        os.system('mkdir Output_data')

    match args.command:
        case "a":
            print("[+] Command Analyse received")
            if not args.snifffile:
                print("[-] Input File not provided")
                exit(0)
            outputfile = args.outputfile
            if not args.outputfile:
                print("[+] Default Output file name : sni.csv")
                outputfile = "sni.csv"

            outputfile = "./Output_data/" + outputfile
            inputfile = "./Input_data/" + args.snifffile
            snie_process_packets("NA", inputfile, outputfile)
        case "s":
            if args.time == None:
                print("[-] Time not provided")
                exit(0)

            if args.snifffile == None:
                print("[-] Sniff file not provided")
                exit(0)

            time = int(args.time)
            snie_sniff_packets(time, args.snifffile)
        case "b":
            if args.time == None:
                print("[-] Time not provided")
                exit(0)

            if args.snifffile == None:
                print("[-] Sniff file not provided")
                exit(0)

            outputfile = args.outputfile
            if not args.outputfile:
                print("[+] Default Output file name : sni.csv")
                outputfile = "sni.csv"

            outputfile = "./Output_data/" + outputfile

            time = int(args.time)
            snie_sniff_and_analyse_packets(time, args.snifffile, outputfile)
        case _:
            print("Invalid command")
            exit(0)