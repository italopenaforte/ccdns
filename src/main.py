import struct
import random

def build_dns_query_message(domain, query_type=1, query_class=1):
    # Generate a random ID for the DNS query
    query_id = random.randint(0, 65535)

    # Flags: QR (1) | OPCODE (4) | AA (1) | TC (1) | RD (1) | RA (1) | Z (3) | RCODE (4)
    flags = 0b0000000100000000  # Standard query with recursion desired
    header = struct.pack('!HHHHHH', query_id, flags, 1, 0, 0, 0)

    # Build the encoded domain name for the question
    labels = domain.split('.')
    encoded_labels = [struct.pack('!B', len(label)) + label.encode('utf-8') for label in labels]
    encoded_labels.append(b'\x00')  # Null terminator for the domain name
    encoded_domain = b''.join(encoded_labels)

    # Query type and query class
    query_type_bytes = struct.pack('!H', query_type)
    query_class_bytes = struct.pack('!H', query_class)

    return header + encoded_domain + query_type_bytes + query_class_bytes

if __name__ == "__main__":
    # Step 1: Build DNS query for dns.google.com
    dns_query = build_dns_query_message("dns.google.com")

    # Convert the query message to hexadecimal for display
    hex_query = ''.join(f'{byte:02x}' for byte in dns_query)
    print(f"DNS Query Message: {hex_query}")
