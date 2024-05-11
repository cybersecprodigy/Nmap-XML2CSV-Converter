import xml.etree.ElementTree as ET
import csv

def parse_nmap_xml(xml_file):
    """
    Parse Nmap XML file and return a list of dictionaries containing host information.
    """
    hosts = []
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    for host in root.findall('host'):
        host_dict = {}
        host_dict['IP'] = host.find('address').get('addr')
        host_dict['Hostname'] = host.find('hostnames').find('hostname').get('name') if host.find('hostnames').find('hostname') is not None else ''
        
        for port in host.find('ports').findall('port'):
            port_number = port.get('portid')
            service = port.find('service')
            port_dict = {
                'Port': port_number,
                'Protocol': port.get('protocol'),
                'Service': service.get('name') if service is not None else '',
                'State': port.find('state').get('state')
            }
            host_dict.update(port_dict)
            hosts.append(host_dict)
            
    return hosts

def write_to_csv(data, csv_file):
    """
    Write Nmap data to a CSV file.
    """
    headers = ['IP', 'Hostname', 'Port', 'Protocol', 'Service', 'State']
    with open(csv_file, 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        writer.writeheader()
        writer.writerows(data)

def convert_xml_to_csv(xml_file, csv_file):
    """
    Convert Nmap XML file to CSV.
    """
    nmap_data = parse_nmap_xml(xml_file)
    write_to_csv(nmap_data, csv_file)

# Example usage:
xml_file = 'nmap_scan.xml'
csv_file = 'nmap_scan.csv'
convert_xml_to_csv(xml_file, csv_file)
print(f"Conversion successful. CSV file saved as '{csv_file}'")
