import struct
import socket
import sys

def parse_binary_file(input_file, output_file):
    """
    Parse a binary file containing IPv4 addresses and ports.
    - First 4 bytes: IPv4 address
    - Bytes 5-6: Port number in little endian

    Args:
        input_file (str): Path to the binary input file
        output_file (str): Path to the text output file
    """
    try:
        with open(input_file, 'rb') as f_in, open(output_file, 'w') as f_out:
            # Read records until end of file
            while True:
                # Read 6 bytes (4 for IP, 2 for port)
                record = f_in.read(6)

                # Break if EOF or incomplete record
                if not record or len(record) < 6:
                    break

                # Extract IP (first 4 bytes)
                ip_bytes = record[0:4]
                ip_str = socket.inet_ntoa(ip_bytes)

                # Extract port (next 2 bytes) - little endian
                port = struct.unpack('>H', record[4:6])[0]

                # Write to output file
                output_line = f"{ip_str}:{port}\n"
                f_out.write(output_line)

        print(f"Parsing complete. Results written to {output_file}")

    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        return
    except IOError as e:
        print(f"I/O error: {e}")
        return
    except Exception as e:
        print(f"Unexpected error: {e}")
        return

if __name__ == "__main__":
    # Check command line arguments
    if len(sys.argv) != 3:
        print("Usage: python script.py input_binary_file output_text_file")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    parse_binary_file(input_file, output_file)
