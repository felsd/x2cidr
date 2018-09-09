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
USAGE: asn2cidr.py [options]\n
OPTIONS:
  -e EXCLUDEFILE  exclude filter for ASNs (optional)
  -i INCLUDEFILE  include filter for ASNs (optional)
  -o OUTPUT       output file (optional, default=output.txt)
  -T THREADS      amount of threads for whois lookups (optional, default=10)
  -mc             match case. if set, filters will be case sensitive
  -h              show this help and exit\n
EXAMPLES:
  asn2cidr.py -e exclude.txt
  asn2cidr.py -e exclude.txt -i include.txt
  asn2cidr.py -e exclude.txt -i include.txt -o file.txt -T 50 -mc
'''

def print_help():
    print(help)
    sys.exit(0)

def get_asn_map(in_filter=None, ex_filter=None, match_case=False):
    asnmap = {}
    r = requests.get('https://www.cidr-report.org/as2.0/autnums.html', stream=True)
    with tempfile.NamedTemporaryFile() as temp:
        temp.write(r.content)
        with open(temp.name, encoding="utf-8", errors='replace') as f:
            for line in f:
                asnres = re.findall('>(AS[0-9]+)<', line)
                if len(asnres) > 0:
                    asn = asnres[0]
                    desc = re.findall('a> (.+)', line)[0]
                    if in_filter is not None:
                        if not str_contains(desc, in_filter, match_case):
                            continue
                    if ex_filter is not None:
                        if str_contains(desc, ex_filter, match_case):
                            continue
                    asnmap[asn] = desc
    return asnmap

def str_contains(input, substrs, match_case):
    if match_case:
        for substr in substrs:
            if substr in input:
                return True
    else:
        for substr in substrs:
            if substr.lower() in input.lower():
                return True
    return False

def resolve_cidr_blocks(asn):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('whois.radb.net', 43))
    s.sendall(bytearray('-i origin '+asn+'\r\n', 'utf-8'))
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
    parser.add_argument('-e')
    parser.add_argument('-i')
    parser.add_argument('-o', default='output.txt')
    parser.add_argument('-T', default=10)
    parser.add_argument('-mc', action='store_true')
    parser.add_argument('-h', action='store_true')
    args = parser.parse_args()

    if args.h:
        print_help()

    exclude_file = args.e
    ex_filter = None
    if exclude_file is not None:
        ex_filter = []
        with open(exclude_file, 'r') as f:
            for line in f:
                if line.strip():
                    ex_filter.append(line.strip())

    include_file = args.i
    in_filter = None
    if include_file is not None:
        in_filter = []
        with open(include_file, 'r') as f:
            for line in f:
                if line.strip():
                    in_filter.append(line.strip())

    output_file = args.o
    open(output_file, 'w').close()
    threads = args.T

    print('--------------------------------------------------------------------------------')
    print(' asn2cidr by dfels')
    print('--------------------------------------------------------------------------------')
    if ex_filter is not None:
        print('> will exclude ASNs containing:\n'+', '.join(ex_filter))
    if in_filter is not None:
        print('> will include ASNs containing:\n'+', '.join(in_filter))


    print('\n> fetching ASNs...')
    asnmap = get_asn_map(ex_filter=ex_filter, in_filter=in_filter, match_case=args.mc)
    print(str(len(asnmap))+' matching ASNs found')

    print('\n> determining CIDR blocks...')
    writer_queue = queue.Queue()
    writer_thread = WriterThread(writer_queue, output_file)
    writer_thread.setDaemon(True)
    writer_thread.start()
    executor = ThreadPoolExecutor(max_workers=threads)
    futures_list = []
    for asn in asnmap:
        futures_list += [executor.submit(resolve_cidr_blocks, asn)]
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
