import dns.resolver
import argparse

def get_parser():
    parser = argparse.ArgumentParser()

    #Target
    parser.add_argument('-d', '--domain', dest='domain', required=False, type=str, help='<*.mysite.*>')
    parser.add_argument('-f', '--file', dest='file', required=False, type=str, help='<Path targets>')
    #Attack
    parser.add_argument('-a', '--axfr', dest='axfr', required=False, type=bool, help='<Try make zone transfer>')
    parser.add_argument('--recursive', dest='recursive', required=False, type=bool, help='<Scan records found>')
    #Output
    parser.add_argument('-v', '--verbose', dest='verbose', required=False, type=bool, help='<Show all progress>')
    parser.add_argument('-o', '--output', dest='output', required=False, type=str, help='<Save results in file>')

    return parser
def get_arguments(parser):
    arguments = parser.parse_args()

    if not arguments.domain and not arguments.file:
        print('Specify a target!')
        print('python3 dnsenum.py --help')
        exit()

    return arguments
def scan(targets):
    records = ['A', 'AAAA', 'NS', 'MX', 'SOA', 'SRV', 'PTR', 'TXT', 'HINFO', 'CNAME']
    for target in targets:
        print(f'\033[1;31mScanning target: {target}\033[1;37m\n')
        for record in records:
            print(f'\033[1;31mTesting {record}:\033[1;37m\n')
            try:
                request = dns.resolver.resolve(target, record)
                for rdata in request:
                    print(f'    {rdata}')
            except dns.resolver.NoAnswer:
                pass

def main():
    #Variables
    parser = get_parser()
    arguments = get_arguments(parser)

    domain = arguments.domain
    file_of_targets = arguments.file
    axfr = arguments.axfr
    recursive = arguments.recursive
    verbose = arguments.verbose
    output = arguments.output

    targets = []
    if domain:
        targets.append(domain)
    if file_of_targets:
        targets.append(file_of_targets)

    scan(targets)

if __name__ == '__main__':
    main()
