#!/usr/bin/env python3
from __future__ import print_function

import argparse
import os
import re
import sys

from ruamel.yaml import YAML
from ruamel.yaml.parser import ParserError

yaml = YAML(typ='safe')

CONFIG_NAME = ".sops.yaml"
CONFIG_CREATION_RULES = "creation_rules"
CONFIG_PATH_REGEX = "path_regex"
KEY_ENCRYPTED_REGEX = "encrypted_regex"
YAML_REGEX = r".*\.ya?ml"
KIND_SECRET_REGEX = r"^kind:\ssecret$"
SOPS_ENCRYPTED_REGEX = r"ENC\[AES256"

match os.getenv('SOPS_PRE_COMMIT_HOOK_OUTPUT_LEVEL'):
    case "verbose":
        verbose = True
        debug = True
        trace = True
    case "debug":
        verbose = False
        debug = True
        trace = True
    case "trace":
        verbose = False
        debug = False
        trace = True
    case _:
        verbose = False
        debug = False
        trace = False

# Find first ".sops.yaml" in the file's tree
def get_sops_config_filename(dirname):
    while True:
        dirname = os.path.dirname(dirname)
#       No separator when top dir
        if dirname != "":
            test = dirname+os.sep+CONFIG_NAME
        else:
            test = CONFIG_NAME
        if verbose:
            print(f"Test: {test}")
        if os.access(test, os.R_OK):
            if verbose:
                print(f"Found configuration: {test}")
            return test
#       If top dir and not found break
        if dirname == "":
            break
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
        print(f"Loaded sops configuration from: {configname}")
    return True, sops_config

# Check to see if any of the keys match a required encrypted_regex
def has_unencrypted_key(leaf,key_regex):
    if isinstance(leaf, dict):
        for k, v in leaf.items():
            # Is the value a dictionary, then check the contents
            if isinstance(v, dict):
                unencrypted_key, message = has_unencrypted_key(v,key_regex)
                if unencrypted_key:
                    return unencrypted_key, message
            elif isinstance(v, list):
                # Is the value a list, then check the contents
                for listItem in v:
                    if not isinstance(listItem, str):
                        unencrypted_key, message = has_unencrypted_key(listItem,key_regex)
                        if unencrypted_key:
                            return unencrypted_key, message
            else:
                if not isinstance(v, str) and not isinstance(v, bool) and not isinstance(v, int) and v is not None:
                    print (f"UNHANDLED TYPE => Key: {k} = {type(v)} = {v}")
                if isinstance(k, str):
                    if re.findall( key_regex, k):
                        print(f"MATCH FOUND - {k}: {v}")
    else:
        if leaf is not None:
            print (f"leaf is a {type(leaf)} = {leaf}")

    return False, f"Matching key NOT found"

# Check for ENC[AES256 in the file
def is_encrypted(filename,key_regex):
    if verbose:
        print(f"Check that file is encrypted {filename}")
    with open(filename, mode="r") as f:
        contents = f.read()
        if re.findall( SOPS_ENCRYPTED_REGEX, contents, flags=re.IGNORECASE | re.MULTILINE ):
            if debug:
                print(f"OK: File is encrypted: {filename}")
            return True, f"OK: File is encrypted: {filename}"

    # Are keys defined for the file match too?
    if key_regex != None:
        if debug:
            print(f"Check {filename} for YAML keys identified by key_regex {key_regex}")
        try:
            with open(filename, mode="r") as fYaml:
                documents = yaml.load_all(fYaml)
                for document in documents:
                    if verbose:
                        print(f"document: {document}")
                    unencrypted_key, message = has_unencrypted_key(document,key_regex)
                    if unencrypted_key:
                        if debug:
                            print(f"Key found and NOT encrypted: {filename}")
                        return False, f"Key found and NOT encrypted: {filename}"
                return True, f"OK: File encryption not required: {filename}"
        except ParserError:
            if debug:
                print(f"NOT YAML and NOT encrypted: {filename}")
            return False, f"NOT YAML and NOT encrypted: {filename}"

    if debug:
        print(f"NOT encrypted: {filename}")
    return False, f"NOT encrypted: {filename}"

# Check for kubernetes kind:secret and ENC[AES256 in the file
def is_encrypted_secret(filename):
    if debug:
        print(f"Check that file kind:secret and is encrypted {filename}")
    with open(filename, mode="r") as f:
        contents = f.read()
        if re.findall( KIND_SECRET_REGEX, contents, flags=re.IGNORECASE | re.MULTILINE ):
            if re.findall( SOPS_ENCRYPTED_REGEX, contents, flags=re.IGNORECASE | re.MULTILINE ):
                if debug:
                    print(f"OK: File is encrypted: {filename}")
                return True, f"OK: File is encrypted: {filename}"
            else:
                if debug:
                    print(f"NOT encrypted: {filename}")
                return False, f"NOT encrypted: {filename}"
        else:
            if verbose:
                print(f"OK: Not kind secret: {filename}")
            return True, f"OK: Not kind secret: {filename}"

# Check the sops status of a file
def check_file(filename):
    sops_config_found, sops_config = get_sops_config(filename)
    if(sops_config_found):
        rules = sops_config.get(CONFIG_CREATION_RULES,[])
        for rule in rules:
            path_regex = rule.get(CONFIG_PATH_REGEX)
            if path_regex:
                if re.findall(path_regex, filename, flags=re.IGNORECASE):
                    path_regex = rule.get(KEY_ENCRYPTED_REGEX)
                    return is_encrypted(filename,path_regex)
            else:
                if verbose:
                    print(f"OK: No regex defined for rule {rule}: {filename}")

    elif re.findall(YAML_REGEX, filename, flags=re.IGNORECASE):
        return is_encrypted_secret(filename)

    if verbose:
        print(f"OK: Not secret file: {filename}")
    return True, f"OK: Not secret file: {filename}"

# The files to check are passed as command line arguments
def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('filenames', nargs='+')
    args = parser.parse_args()

    failed_messages = []

    # if trace:
    #     print(f"Check: {args.filenames}")

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
