#!/bin/env python3
import sys
import os
import json
import binascii
import getopt
import re
from keepassxc_proxy_client import protocol

debug = 0

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

def debug_print(message):
    if debug:
        print(f"[DEBUG] {message}", file=sys.stderr)

def error(message):
    print(f"[ERROR] {message}", file=sys.stderr)
    sys.exit(1)

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
        error(str(err))

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

    # Validate URL format
    if not re.match(r'^[a-z0-9]+://', url):
        error("URL must start with a valid scheme (e.g., https://, ssh://).")

    try:
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
            debug_print("Association created and saved to {} with name '{}' and hex-encoded public key.".format(keyfile_path, name))

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
                debug_print("Loaded association from {}.".format(keyfile_path))
            except (json.JSONDecodeError, ValueError, binascii.Error) as e:
                error(f"Failed to load association: {e}\n\nPlease delete the keyfile and re-run the script to re-associate.")

        # Test association
        try:
            if not connection.test_associate():
                error("Association test failed. Please re-associate.")
        except protocol.ResponseUnsuccesfulException as e:
            error_data = e.args[0] if e.args else {}
            error_message = error_data.get("error", "Unknown error")
            error_code = error_data.get("errorCode", "1")
            error(f"Connection error: {error_message} (Code: {error_code})")

        # Retrieve logins for the specified URL
        try:
            logins = connection.get_logins(url)
            if logins:
                for login in logins:
                    formatted_output = (output_format
                                        .replace('%n', login.get('name', 'N/A'))
                                        .replace('%l', login.get('login', 'N/A'))
                                        .replace('%p', login.get('password', 'N/A')))
                    print(formatted_output, end=("" if not add_newline else "\n"))
            else:
                error(f"No logins found for URL: {url}")
        except protocol.ResponseUnsuccesfulException as e:
            error_data = e.args[0] if e.args else {}
            error_message = error_data.get("error", "Unknown error")
            error(f"Error retrieving logins: {error_message}")

    except Exception as e:
        error(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
