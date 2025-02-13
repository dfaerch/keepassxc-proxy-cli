#!/bin/env python3
import sys
import os
import json
import binascii
import getopt
import re
import time
from keepassxc_proxy_client import protocol

version = 1.1
debug = 0

# -------------


class KeepassClientSignalWorkaround(protocol.Connection):
    """Custom Connection class that handles unexpected KeePassXC signals properly."""

    def __init__(self):
        super().__init__()  # Initialize the parent class
        self.last_signal = None  # Store the last signal message

    def get_unencrypted_response(self):
        """Fetches a response from KeePassXC, storing last signal messages and skipping them."""
        data = []

        while True:
            new_data = self.socket.recv(4096)
            if new_data:
                decoded_data = new_data.decode('utf-8')
                data.append(decoded_data)
            else:
                break
            if len(new_data) < 4096:
                break

        response = json.loads(''.join(data))

        # Detect simple signal messages like { "action": "database-unlocked" }
        if isinstance(response, dict) and len(response) == 1 and "action" in response:
            self.last_signal = response["action"]  # Store signal
            debug_print(f"[DEBUG] Stored last signal: {self.last_signal}")
            return self.get_unencrypted_response()  # Fetch next response instead

        return response  # Return valid response

    # Unused for now, but if we get a "user-closed-password-dialog"-ish signal one day, we can use it
    # to break out of the wait loop.
    def get_last_signal(self):
        """Retrieves and clears the last received signal message."""
        signal = self.last_signal
        self.last_signal = None  # Clear after reading
        return signal


# -------------

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
  -w <sec>                       Wait max number of sec for the user to enter password in keepass. 0=no-wait. (default=30)
  -v                             Print version
  -h, --help                     Display this help message.
"""
    print(help_text)

def debug_print(message):
    if debug:
        import inspect
        frame = inspect.currentframe().f_back  # Get the caller's frame
        lineno = frame.f_lineno  # Get the line number of the caller
        print(f"[DEBUG:{lineno}] {message}", file=sys.stderr)

def error(message):
    print(f"[ERROR] {message}", file=sys.stderr)
    sys.exit(1)

def main():
    # Default values
    keyfile_path = None
    url = None
    output_format = "Name: %n\nLogin: %l\nPassword: %p\n"
    add_newline = True  # Default to adding newline after each entry
    max_wait = 30
    retry_sleep = 1

    # Parse command-line arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:k:f:nw:vh", ["url=", "keyfile=", "format=", "help"])
    except getopt.GetoptError as err:
        error(str(err))

    for opt, arg in opts:
        if opt in ("-u", "--url"):
            url = arg
        elif opt in ("-k", "--keyfile"):
            keyfile_path = arg
        elif opt in ("-f", "--format"):
            output_format = arg
        elif opt == "-w":
            try:
                max_wait = int(arg)
            except ValueError:
                error("int expected for -w")
        elif opt == "-n":
            add_newline = False
        elif opt == "-v":
            print(version)
            sys.exit(0)
        elif opt in ("-h", "--help"):
            print_help()
            sys.exit(0)

    # Ensure required arguments are provided
    if not url or not keyfile_path:
        print_help()
        sys.exit(1)

    # Validate URL format
    if not re.match(r'^[a-z0-9]+://', url):
        error("URL must start with a scheme (e.g., https://, ssh://).")

    try:
        # Initialize connection
        connection = KeepassClientSignalWorkaround()
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
                trigger_unlock = True # Triggers keepassxc gui to pop up a dialog for entering password
                start_time = time.time()
                stored_nonce = None  # Store nonce if received

                while True:
                    error_code = "0"
                    e = None

                    try:
                        response = connection.test_associate(trigger_unlock)  # Try associating
                    except protocol.ResponseUnsuccesfulException as e:
                        error_data = e.args[0] if e.args else {}
                        error_message = error_data.get("error", "Unknown error")
                        error_code = error_data.get("errorCode", "1")

                    trigger_unlock = False  # Only trigger unlock once

                    if max_wait == "0" or error_code == "0":  # Don't retry
                        break

                    if error_code != "1":
                        print(error_code)
                        raise e  # Only raise the original exception if it's not a "database locked" error

                    if time.time() - start_time >= max_wait:
                        error(f"Timeout while waiting for user to unlock database")
                        break

                    debug_print("Waiting for unlocking of database")
                    time.sleep(retry_sleep)

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
        if debug:
           raise(e)
        error(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
