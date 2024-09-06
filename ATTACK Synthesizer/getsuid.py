import os
import re
import yaml

def extract_binaries(content, pattern):
    matches = pattern.findall(content)
    binaries = set()
    for match in matches:
        parts = match.split()
        for part in parts:
            if part.startswith('/'):
                clean_part = re.sub(r'\x1b\[[0-9;]*m', '', part)
                binary_name = os.path.basename(clean_part).strip()
                binaries.add(binary_name)
    return binaries

def read_gtfobins(binary, gtfobins_dir):
    file_path = os.path.join(gtfobins_dir, f"{binary}.md")
    if not os.path.isfile(file_path):
        return None
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def extract_code_from_yaml(content):
    code_segments = []
    documents = content.split('---')
    for document in documents:
        try:
            data = yaml.safe_load(document)
            if data and 'functions' in data:
                for function in data['functions'].values():
                    for entry in function:
                        if 'code' in entry:
                            if isinstance(entry['code'], str):
                                code_segments.append(entry['code'])
                            elif isinstance(entry['code'], list):
                                code_segments.extend(entry['code'])
        except yaml.YAMLError as e:
            print(f"YAML error: {e}")
    return code_segments

def get_misconfigured_with_content(pattern, gtfobins_dir):
    filename = 'results_interesting_perms_files.txt'

    if not os.path.isfile(filename):
        return []

    with open(filename, 'r') as file:
        content = file.read()

    binaries = extract_binaries(content, pattern)
    misconfigured_list = []

    for binary in binaries:
        binary_content = read_gtfobins(binary, gtfobins_dir)
        if binary_content:
            code_segments = extract_code_from_yaml(binary_content)
            if code_segments:
                misconfigured_list.append((f"/usr/bin/{binary}", code_segments))
    
    return misconfigured_list

def get_misconfigured_suid_with_content():
    suid_pattern = re.compile(r'^-rws.*', re.MULTILINE)
    return get_misconfigured_with_content(suid_pattern, 'GTFOBins.github.io/_gtfobins/')

def get_misconfigured_sgid_with_content():
    sgid_pattern = re.compile(r'^-rwx.*', re.MULTILINE)
    return get_misconfigured_with_content(sgid_pattern, 'GTFOBins.github.io/_gtfobins/')

def main():
    suid_list = get_misconfigured_suid_with_content()
    sgid_list = get_misconfigured_sgid_with_content()

    print("SUID Content:\n")
    for binary, code_segments in suid_list:
        print(binary)
        for code in code_segments:
            print(code)
        print()

    print("\nSGID Content:\n")
    for binary, code_segments in sgid_list:
        print(binary)
        for code in code_segments:
            print(code)
        print()

if __name__ == "__main__":
    main()
