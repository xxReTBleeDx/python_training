from scapy.all import TCP, rdpcap
import collections
import os
import re
import sys
import zlib

# Dir where we gonna save extracted pics
OUTDIR = '/root/Desktop/pictures'
# Dir where the pcap file is located
PCAPS = '/root/Downloads'

# Named tuple to hold HTTP responses (header + payload)
Response = collections.namedtuple('Response', ['header', 'payload'])

# Function to get HTTP header from the packet payload
def get_header(payload):
    try:
        # Extract raw header (everything before '\r\n\r\n')
        header_raw = payload[:payload.index(b'\r\n\r\n')+2]
    except ValueError:
        # If header can't be found, log it and return None
        sys.stdout.write('-')
        sys.stdout.flush()
        return None
    
    # Use regex to find headers and convert them to a dict
    header = dict(re.findall(r'(?P<name>.*?): (?P<value>.*?)\r\n', header_raw.decode()))
    
    # If no 'Content-Type' in header, it's not what we're lookin for
    if 'Content-Type' not in header:
        return None
    
    return header

# Class to handle pcap processing and HTTP response extraction
class Recapper:
    def __init__(self, fname):
        # Constructor: we gonna load the pcap file here
        pass
    
    def get_responses(self):
        # Method to get HTTP responses from the pcap file
        # It should filter and reassemble TCP sessions from packets
        # Then extract responses that were sent over HTTP (port 80)
        pass
    
    def write(self, content_name):
        # Method to write the extracted contents (e.g., images) to disk
        # For each HTTP response containing the desired content (like images),
        # it should save the file to the OUTDIR directory.
        pass

# Main execution block
if __name__ == '__main__':
    # Build the path to the pcap file
    pfile = os.path.join(PCAPS, 'pcap.pcap')
    
    # Create Recapper instance with the pcap file
    recapper = Recapper(pfile)
    
    # Call method to extract HTTP responses
    recapper.get_responses()
    
    # Call method to write extracted images to disk
    recapper.write('image')
