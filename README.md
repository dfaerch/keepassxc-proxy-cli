# keepassxc-proxy-cli
CLI that allows you to talk to KeepassXC's GUI instance, the same way the browser plugins do.

## Description

keepassxc-proxy-cli uses the KeepassXC-proxy protocol to talk to a running
KeepassXC GUI instance, allowing you to search users and get passwords as long as the database is unlocked.

This tool was written to allow integration with WezTerm via the 
[PassRelay](https://github.com/dfaerch/passrelay.wezterm) WezTerm plugin.

## Usage

```bash
keepassxc-proxy-cli.py -u <url> -k <keyfile_path> [-f <output_format>] [-n]
```

### Options

```text
-u, --url <url>                URL to search in KeePassXC.
-k, --keyfile <keyfile_path>   Path to the keyfile to store the association.
-f, --format <output_format>   Specify the output format (default: "Name: %n\nLogin: %l\nPassword: %p\n").
                                 Placeholders:
                                   %n - Entry name
                                   %l - Login/username
                                   %p - Password
-n                             Suppress newline after each entry's output.
-h, --help                     Display this help message.
```

`url`: the url that will be searches for in KeepassXC.  Must start with a scheme (eg. https://, whatever://).

`keyfile`: After connecting to KeepassXC for the fist time, a key will be stored here, to be read for future connections. (eg ~/.keepassxc_proxy_cli.key). It will not overwrite existing file.

## Setup

In KeepassXC's GUI, you must enable browser integration. Go to **Tools -> Settings**
to enable. Only the *"enable browser integration"* checkbox matters for this.

Install `keepassxc_proxy_client` for Python:

```bash
pip install keepassxc_proxy_client
```

Depending on your distro, it may be simpler for you to use a Python virtual environment (venv). See under Examples.

## Examples

### Command Line Usage

```bash
$ ./keepassxc-proxy-cli.py -k ~/.keepassxc-proxy-cli.key -u https://github.com
Name: https://github.com
Login: testuser
Password: TestPass
```

#### Format examples

```bash
$ ./keepassxc-proxy-cli.py -k ~/.keepassxc-proxy-cli.key -u https://github.com -f "%p"
TestPass
```

```bash
$ ./keepassxc-proxy-cli.py -k ~/.keepassxc-proxy-cli.key -u https://github.com -f "'%l:%p'"
'testuser:TestPass'
```


### Using a Virtual Environment

#### Create venv

```bash
cd keepassxc-proxy-client
python3 -m venv venv
```

#### Run in venv

```bash
bash -c "source /path/to/keepassxc-proxy-cli/venv/bin/activate && /path/to/keepassxc-proxy-cli/keepassxc-proxy-cli.py -k ~/.keepassxc-proxy-cli.key -u https://github.com"
Name: https://github.com
Login: testuser
Password: TestPass
```
