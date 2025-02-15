#!/usr/bin/env python3
from __future__ import print_function

import argparse
import os
import re
from ruamel.yaml import YAML
from ruamel.yaml.parser import ParserError

yaml = YAML(typ='safe')

verbose = False
debug = False

CONFIG_NAME = ".sops.yaml"
CONFIG_CREATION_RULES = "creation_rules"
CONFIG_PATH_REGEX = "path_regex"
YAML_REGEX = r".*\.ya?ml"
KIND_SECRET_REGEX = r"^kind:\ssecret$"
SOPS_ENCRYPTED_REGEX = r"ENC.AES256"

# Find ".sops.yaml" in the files tree
def get_sops_config_filename(dirname):
#   Always check in project root first
    if os.access(CONFIG_NAME, os.R_OK):
        return CONFIG_NAME
#   Go up the tree if not in root
    dirname = os.path.dirname(dirname)
    while dirname!="":
        test = dirname+os.sep+CONFIG_NAME
        if debug:
            print("Test for {0}".format(test))
        if os.access(test, os.R_OK):
            return test
        dirname = os.path.dirname(dirname)
    return ""

# Load ".sops.yaml" if found
def get_sops_config(filename):
    configname = get_sops_config_filename(filename)
    if configname=="":
        if debug:
            print("No sops configuration not found")
        return False, "sops configuration not found"
    with open(configname) as f:
        try:
            sops_config = yaml.load(f)
        except ParserError:
            return False, "sops configuration not YAML"
    if verbose:
        print("Loaded sops configuration from: {0}".format(configname))
    return True, sops_config

def is_encrypted(filename):
    if verbose:
        print("Check that file is encrypted {0}".format(filename))
    with open(filename, mode="r") as f:
        contents = f.read()
        if re.findall( SOPS_ENCRYPTED_REGEX, contents, flags=re.IGNORECASE | re.MULTILINE ):
            if debug:
                print("OK: File is encrypted: {}".format(filename))
            return True, "OK: File is encrypted: {}".format(filename)
    if debug:
        print("NOT encrypted: {}".format(filename))
    return False, "NOT encrypted: {}".format(filename)

def is_encrypted_secret(filename):
    if debug:
        print("Check that file kind:secret and is encrypted {0}".format(filename))
    with open(filename, mode="r") as f:
        contents = f.read()
        if re.findall( KIND_SECRET_REGEX, contents, flags=re.IGNORECASE | re.MULTILINE ):
            if re.findall( SOPS_ENCRYPTED_REGEX, contents, flags=re.IGNORECASE | re.MULTILINE ):
                if debug:
                    print("OK: File is encrypted: {0}".format(filename))
                return True, "OK: File is encrypted: {0}".format(filename)
            else:
                if debug:
                    print("NOT encrypted: {0}".format(filename))
                return False, "NOT encrypted: {0}".format(filename)
        else:
            if debug:
                print("OK: Not kind secret: {0}".format(filename))
            return True, "OK: Not kind secret: {0}".format(filename)

def check_file(filename):
    sops_config_found, sops_config = get_sops_config(filename)
    if(sops_config_found):
        rules = sops_config.get(CONFIG_CREATION_RULES,[])
        for rule in rules:
            path_regex = rule.get(CONFIG_PATH_REGEX)
            if path_regex:
                if re.findall(path_regex, filename, flags=re.IGNORECASE):
                    return is_encrypted(filename)
            else:
                if debug:
                    print("OK: No regex defined for rule {0}: {1}".format(rule,filename))

    elif re.findall(YAML_REGEX, filename, flags=re.IGNORECASE):
        return is_encrypted_secret(filename)

    if debug:
        print("OK: Not secret file: {0}".format(filename))
    return True, "OK: Not secret file: {0}".format(filename)

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('filenames', nargs='+')
    args = parser.parse_args()

    failed_messages = []

    for f in args.filenames:
        is_valid, message = check_file(f)

        if not is_valid:
            failed_messages.append(message)

    if failed_messages:
        print('\n'.join(failed_messages))
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
