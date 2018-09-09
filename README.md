# x2cidr
## asn2cidr
Searches for ASNs, resolves their CIDR blocks and writes them to a file.

Using an inclusive and/or exclusive filter it retrieves all matching ASNs from ```cidr-report.org```.
Then it resolves the ASN's CIDR blocks by querying the RADb whois server and writes the results to a file.

```
USAGE: asn2cidr.py [options]

OPTIONS:
  -e EXCLUDEFILE  exclude filter for ASNs (optional)
  -i INCLUDEFILE  include filter for ASNs (optional)
  -o OUTPUT       output file (optional, default=output.txt)
  -T THREADS      amount of threads for whois lookups (optional, default=10)
  -mc             match case. if set, filters will be case sensitive
  -h              show this help and exit
  
EXAMPLES:
  asn2cidr.py -e exclude.txt
  asn2cidr.py -e exclude.txt -i include.txt
  asn2cidr.py -e exclude.txt -i include.txt -o file.txt -T 50 -mc
```
## ip2cidr
Resolves the CIDR blocks of IPs by querying the RADb whois server and writes them to a file.

```
USAGE: ip2cidr.py [options]

OPTIONS:
  -i INPUTFILE  IP input file
  -o OUTPUT     output file (optional, default=output.txt)
  -T THREADS    amount of threads for whois lookups (optional, default=10)
  -h            show this help and exit
  
EXAMPLES:
  ip2cidr.py -i ips.txt
  ip2cidr.py -i ips.txt -o file.txt -T 50
```
