#!/bin/env python3
import sys
import os
import json
import binascii
import getopt
from keepassxc_proxy_client import protocol

def print_help():
    help_text = """
Usage: script.py -u <url> -k <keyfile_path> [-f <output_format>] [-n]

Options:
  -u, --url <url>                URL to search in KeePassXC.
  -k, --keyfile <keyfile_path>   Path to the keyfile to store association.
  -f, --format <output_format>   Specify the output format (default: "Name: %n\\nLogin: %l\\nPassword: %p\\n").
                                 Placeholders:
                                   %n - Entry name
                                   %l - Login/username
                                   %p - Password
  -n                             Suppress newline after each entry's output.
  -h, --help                     Display this help message.
"""
    print(help_text)

def main():
    # Default values
    keyfile_path = None
    url = None
    output_format = "Name: %n\nLogin: %l\nPassword: %p\n"
    add_newline = True  # Default to adding newline after each entry

    # Parse command-line arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:k:f:nh", ["url=", "keyfile=", "format=", "help"])
    except getopt.GetoptError as err:
        print(str(err))
        print_help()
        sys.exit(1)

    for opt, arg in opts:
        if opt in ("-u", "--url"):
            url = arg
        elif opt in ("-k", "--keyfile"):
            keyfile_path = arg
        elif opt in ("-f", "--format"):
            output_format = arg
        elif opt == "-n":
            add_newline = False
        elif opt in ("-h", "--help"):
            print_help()
            sys.exit(0)

    # Ensure required arguments are provided
    if not url or not keyfile_path:
        print_help()
        sys.exit(1)

    # Initialize connection
    connection = protocol.Connection()
    connection.connect()

    if not os.path.exists(keyfile_path):
        # Associate with KeePassXC and dump association details
        connection.associate()
        name, public_key = connection.dump_associate()

        # Hex encode the binary public key for storage
        public_key_hex = binascii.hexlify(public_key).decode('utf-8')

        association = {'id': name, 'key': public_key_hex}

        # Save association to keyfile
        with open(keyfile_path, 'w') as keyfile:
            json.dump(association, keyfile)
        print(f"Association created and saved to {keyfile_path} with name '{name}' and hex-encoded public key.")

    else:
        # Load existing association
        try:
            with open(keyfile_path, 'r') as keyfile:
                association = json.load(keyfile)
            # Ensure association contains 'id' and 'key'
            if not isinstance(association, dict) or 'id' not in association or 'key' not in association:
                raise ValueError("Invalid association file format.")

            # Decode the hex-encoded public key back to binary
            public_key = binascii.unhexlify(association['key'])
            connection.load_associate(association['id'], public_key)
            print(f"Loaded association from {keyfile_path}.")
        except (json.JSONDecodeError, ValueError, binascii.Error) as e:
            print(f"Failed to load association: {e}")
            print("Please delete the keyfile and re-run the script to re-associate.")
            sys.exit(1)

    # Test association
    if not connection.test_associate():
        print("Association test failed. Please re-associate.")
        sys.exit(1)

    # Retrieve logins for the specified URL
    logins = connection.get_logins(url)
    if logins:
        for login in logins:
            formatted_output = (output_format
                                .replace('%n', login.get('name', 'N/A'))
                                .replace('%l', login.get('login', 'N/A'))
                                .replace('%p', login.get('password', 'N/A')))
            print(formatted_output, end=("" if not add_newline else "\n"))
    else:
        print(f"No logins found for URL: {url}")

if __name__ == "__main__":
    main()
