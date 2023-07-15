from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
import time
import multiprocessing
import argparse
import os
from snie_pkt_sniff import snie_sniff_and_analyse_packets

def open_browser(url, timeout):
    driver = webdriver.Firefox()
    driver.get(url)
    time.sleep(timeout - 10)
    driver.close()
    driver.quit()

def capture_and_analyse(url, timeout):
    print("[+] Initialising environment")
    if not os.path.exists("./Output_data"):
        os.system('mkdir Output_data')
    
    if not os.path.exists("./Input_data"):
        os.system('mkdir Output_data')

    url = url.replace("https://", "")
    url = url.replace(".", "_")
    sniff_file = url + ".pcap"
    outputfile = f"./Output_data/{url}.csv" 
    snie_sniff_and_analyse_packets(timeout, sniff_file, outputfile)

def open_capture_and_analyse(url, timeout):
    p1 = multiprocessing.Process(target=open_browser, args=(url, timeout))
    p2 = multiprocessing.Process(target=capture_and_analyse, args=(url, timeout,))
    
    p1.start()
    p2.start()

    p1.join()
    p2.join()

if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="URL File")
    parser.add_argument("-t", "--time", help="Time in seconds to sniff")

    args=parser.parse_args()

    if args.file == None:
        print("[-] File not provided")
        exit(0)
    
    if args.time == None:
        print("[-] Time not provided")
        exit(0)
    urls = []
    with open(args.file, "r") as f:
        for j in f:
            if j.strip() != "":
                urls.append(j.strip())

    t = int(args.time)

    for url in urls:
        print(f"[+] Processing {url}")
        open_capture_and_analyse(url, t)
    
    print("[+] Done")
            

    