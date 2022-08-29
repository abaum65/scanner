import nmap3
import time
import argparse
import sys
import json

def get_hosts(data):
    hosts = set()
    keys = data.keys()
    for key in keys:
        if 'ports' in data[key]:
            for port in data[key]['ports']:
                if port['state'] == 'open':
                    hosts.add(key)
    return ' '.join(str(h) for h in hosts)

def write_json_file(data, file_name):
    with open(file_name, 'w') as f:
        json.dump(data, f)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-s', '--subnet', help='Subnet or IP eg 10.20.135.0/24 this is required')
    parser.add_argument(
        '-t', '--timing', help='This will change the -T value for the speed of the scan 0-5 the higher the number the faster the scan if this is missing it will default to 2')
    parser.add_argument('-f', '--file_prefix',
                        help='This will will be the prefix for the saved files eg [prefix].initialscan.json. If this is missing it will default to the subnet')
    args = parser.parse_args()
    subnet = ''
    timing = ''
    prefix = ''
    if not args.subnet:
        print('-s is required')
        sys.exit()
    else:
        subnet = args.subnet
    if not args.timing:
        timing = str(2)
    else:
        timing = str(args.timing)
    if not args.file_prefix:
        prefix = subnet.replace('/', '')
    else:
        prefix = args.file_prefix
    print("start")
    start_time = time.time()
    nmap = nmap3.Nmap()
    initial = nmap.scan_top_ports(
        subnet, args='-T' + timing + ' -Pn -oN ' + prefix + '.inital.txt')
    write_json_file(initial, prefix + '.initial.json')
    hosts = get_hosts(initial)
    results = nmap.scan_top_ports(
        hosts, args='-O -sV --script=default,safe -T' + timing + ' -Pn -oN ' + prefix + '.full.txt')
    write_json_file(results, prefix + '.full.json')
    total_time = int(time.time() - start_time) / 60
    print("--- %s Minutes ---" % total_time)

if __name__ == '__main__':
    main()
