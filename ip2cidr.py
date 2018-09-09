import requests
import tempfile
import re
import socket
from tqdm import tqdm
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import argparse
import time

help = '''
USAGE: ip2cidr.py [options]\n
OPTIONS:
  -i INPUTFILE  IP input file
  -o OUTPUT     output file (optional, default=output.txt)
  -T THREADS    amount of threads for whois lookups (optional, default=10)
  -h            show this help and exit\n
EXAMPLES:
  ip2cidr.py -i ips.txt
  ip2cidr.py -i ips.txt -o file.txt -T 50
'''

def print_help():
    print(help)
    sys.exit(0)

def resolve_cidr_blocks(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('whois.radb.net', 43))
    s.sendall(bytearray(ip+'\r\n', 'utf-8'))
    response = ''
    while True:
        d = s.recv(4096)
        response += str(d)
        if d == b'':
            break
    s.close()
    blocks = re.findall('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', response)
    for block in blocks:
        writer_queue.put(block)

class WriterThread(threading.Thread):
    def __init__(self, queue, output_file):
        self.q = queue
        self.output_file = output_file
        threading.Thread.__init__(self)
    def run(self):
        while True:
            q_size = self.q.qsize()
            if q_size>0:
                with open(self.output_file, 'a+') as f:
                    for i in range(q_size):
                        f.write(self.q.get()+'\n')
                        self.q.task_done()
            time.sleep(0.1)

try:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-i')
    parser.add_argument('-o', default='output.txt')
    parser.add_argument('-T', default=10)
    parser.add_argument('-h', action='store_true')
    args = parser.parse_args()

    if not args.i or args.h:
        print_help()

    input_file = args.i
    output_file = args.o
    open(output_file, 'w').close()
    threads = args.T

    print('--------------------------------------------------------------------------------')
    print(' ip2cidr by dfels')
    print('--------------------------------------------------------------------------------')

    print('\n> determining CIDR blocks...')
    writer_queue = queue.Queue()
    writer_thread = WriterThread(writer_queue, output_file)
    writer_thread.setDaemon(True)
    writer_thread.start()
    executor = ThreadPoolExecutor(max_workers=threads)
    futures_list = []
    with open(input_file, 'r') as f:
        for ip in f:
            futures_list += [executor.submit(resolve_cidr_blocks, ip)]

    for f in tqdm(as_completed(futures_list), total=len(futures_list)):
        pass
    writer_queue.join()

    print('\n> removing duplicates...')
    with open(output_file, 'r') as f:
        lines = set(f)
    with open(output_file, 'w') as f:
        for line in tqdm(lines):
            f.write(line.strip()+'\n')

    print('\n> done: '+str(len(lines))+' CIDR blocks written to '+output_file)

except (KeyboardInterrupt, SystemExit):
    os._exit(0)
