import iocextract
import ioc_finder
import yara
import json
import os
import datetime
import tkinter as tk
from tkinter import filedialog

def extract_iocs_from_text(text_content):
    """
    Extracts various IOCs from a given text string using iocextract and ioc-finder.
    """
    iocs = {}

    # === iocextract IOCs ===
    iocs['urls'] = list(iocextract.extract_urls(text_content))
    iocs['ips'] = list(iocextract.extract_ips(text_content))
    iocs['emails'] = list(iocextract.extract_emails(text_content))
    iocs['md5'] = list(iocextract.extract_md5_hashes(text_content))
    iocs['sha1'] = list(iocextract.extract_sha1_hashes(text_content))
    iocs['sha256'] = list(iocextract.extract_sha256_hashes(text_content))

    # === ioc-finder IOCs ===
    found = ioc_finder.find_iocs(text_content)

    # Add all supported IOC types by ioc-finder
    iocs.update({
        'asn': found.get('asns', []),
        'btc_addresses': found.get('bitcoin_addresses', []),
        'cves': found.get('cves', []),
        'domains': found.get('domains', []),
        'email_addresses': found.get('email_addresses', []),
        'ga_tracking_ids': found.get('ga_tracking_ids', []),
        'google_adsense_ids': found.get('google_adsense_ids', []),
        'ipv4': found.get('ipv4s', []),
        'ipv6': found.get('ipv6s', []),
        'mac_addresses': found.get('mac_addresses', []),
        'skype_usernames': found.get('skype_usernames', []),
        'ssl_fingerprints': found.get('ssl_fingerprints', []),
        'telegram_channels': found.get('telegram_channels', []),
        'urls_iocfinder': found.get('urls', []),
        'user_agents': found.get('user_agents', []),
        'uuid': found.get('uuids', []),
    })

    # === YARA Rule Matching ===
    iocs['yara_matches'] = extract_yara_matches(text_content)

    return iocs

def extract_yara_matches(text_content):
    """
    Apply basic YARA rules to find keyword matches in the text.
    You can customize these rules or load from .yar files.
    """
    yara_rules = """
    rule suspicious_keywords {
        strings:
            $malicious = "malicious" nocase
            $backdoor = "backdoor" nocase
            $trojan = "trojan" nocase
        condition:
            any of them
    }
    """
    try:
        rules = yara.compile(source=yara_rules)
        matches = rules.match(data=text_content)
        return [match.rule for match in matches]
    except yara.SyntaxError as e:
        return [f"YARA syntax error: {e}"]

def choose_input_file():
    """
    Opens a file selection dialog and returns the selected file path.
    """
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(
        title="Select a text file containing IOCs",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    return file_path

def main():
    file_path = choose_input_file()
    if not file_path:
        print("No file selected.")
        return

    with open(file_path, 'r', encoding='utf-8') as f:
        text_content = f.read()

    iocs = extract_iocs_from_text(text_content)

    # Timestamp for output filename
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_filename = f"extracted_iocs_{timestamp}.json"

    # Save output file in script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, output_filename)

    with open(output_path, 'w', encoding='utf-8') as out_file:
        json.dump(iocs, out_file, indent=4)

    print(f"\n✅ IOCs extracted and saved to: {output_path}")

if __name__ == "__main__":
    main()
