
import datetime
import re
import json
from ipaddress import ip_address, AddressValueError # For IP validation

# --- Configuration for IOC Types (consistent with previous) ---
IOC_TYPE_IP = "ip_address"
IOC_TYPE_DOMAIN = "domain"
IOC_TYPE_URL = "url"
# Add other IOC types as needed (e.g., for file hashes if analyzing file transfers)

# --- Helper Functions ---
def convert_pyshark_timestamp_to_iso(pyshark_packet_object):
    """Converts pyshark packet's sniff_time to ISO 8601 UTC."""
    try:
        # pyshark_packet_object.sniff_timestamp is a float (Unix epoch)
        dt_object = datetime.datetime.fromtimestamp(float(pyshark_packet_object.sniff_timestamp), tz=datetime.timezone.utc)
        return dt_object.isoformat()
    except Exception:
        # Fallback if sniff_timestamp is not available or invalid
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

def is_private_ip(ip_str):
    """Checks if an IP address is in a private range or loopback."""
    if not isinstance(ip_str, str):
        return False
    try:
        ip = ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except AddressValueError:
        return False # Not a valid IP address format

def safe_getattr(obj, attr, default=None):
    """Safely gets an attribute from a pyshark layer object."""
    try:
        # Pyshark attributes can sometimes be lists of values (e.g., http.host if multiple headers)
        # For simplicity, we'll often take the first if it's a list, or handle specific cases.
        val = getattr(obj, attr, default)
        if isinstance(val, list) and len(val) > 0:
            return val[0] # Take the first occurrence if it's a list
        return val
    except Exception:
        return default

# --- Main Processing Function ---
def extract_info_from_pyshark_packet(packet_data_dict, raw_pyshark_packet):
    """
    Processes a packet (from SimpleShark's output) to extract IOCs and features.

    Args:
        packet_data_dict (dict): The dictionary produced by SimpleShark's process_packet.
                                 Example: {'timestamp', 'protocol', 'src_ip', 'src_port', 
                                          'dst_ip', 'dst_port', 'size', 'info'}
        raw_pyshark_packet (pyshark.packet.packet.Packet): The raw pyshark packet object.

    Returns:
        list: A list of dictionaries, where each dictionary is an extracted event/IOC.
              Returns an empty list if no relevant info/IOCs are extracted.
    """
    extracted_events = []
    
    # Base information from SimpleShark's pre-processed data
    base_event_info = {
        "capture_timestamp": convert_pyshark_timestamp_to_iso(raw_pyshark_packet), # Use more precise sniff_time
        "log_source_type": "pyshark_live_capture",
        "highest_layer_protocol": packet_data_dict.get('protocol', 'Unknown').upper(),
        "source_ip": packet_data_dict.get('src_ip', 'N/A'),
        "source_port": packet_data_dict.get('src_port', 'N/A'),
        "destination_ip": packet_data_dict.get('dst_ip', 'N/A'),
        "destination_port": packet_data_dict.get('dst_port', 'N/A'),
        "packet_size": packet_data_dict.get('size', 0),
        "transport_protocol": None, # Will be populated based on layers
        # "raw_packet_summary": str(raw_pyshark_packet) # Optional: for debugging, can be very verbose
    }

    # --- Extract Transport Protocol ---
    if hasattr(raw_pyshark_packet, 'tcp'):
        base_event_info["transport_protocol"] = "TCP"
    elif hasattr(raw_pyshark_packet, 'udp'):
        base_event_info["transport_protocol"] = "UDP"
    elif hasattr(raw_pyshark_packet, 'icmp'):
        base_event_info["transport_protocol"] = "ICMP"
    
    # --- IP Address IOCs (from base_event_info, filtering private) ---
    src_ip = base_event_info["source_ip"]
    dst_ip = base_event_info["destination_ip"]

    if src_ip != 'N/A' and not is_private_ip(src_ip):
        extracted_events.append({
            **base_event_info,
            "ioc_type": IOC_TYPE_IP,
            "ioc_value": src_ip,
            "ip_role": "source"
        })
    
    if dst_ip != 'N/A' and not is_private_ip(dst_ip):
        extracted_events.append({
            **base_event_info,
            "ioc_type": IOC_TYPE_IP,
            "ioc_value": dst_ip,
            "ip_role": "destination"
        })

    # --- DNS Layer Processing ---
    if hasattr(raw_pyshark_packet, 'dns'):
        dns_layer = raw_pyshark_packet.dns
        dns_event_info = {**base_event_info} # Copy base info for DNS specific events

        # Queries
        queried_name = safe_getattr(dns_layer, 'qry_name')
        if queried_name:
            dns_event_info["dns_query_name"] = queried_name
            dns_event_info["dns_query_type"] = safe_getattr(dns_layer, 'qry_type_name', safe_getattr(dns_layer, 'qry_type'))
            extracted_events.append({
                **dns_event_info,
                "ioc_type": IOC_TYPE_DOMAIN,
                "ioc_value": queried_name
            })

        # Answers (can be multiple)
        # Pyshark stores answers in fields like 'a' (for A records), 'cname', 'ns', etc.
        # It also has 'resp_name' and 'resp_type' if you iterate through all answers.
        # For simplicity, let's check common record types.
        
        # A records (IPv4)
        if hasattr(dns_layer, 'a'):
            answers_a = dns_layer.a
            if not isinstance(answers_a, list): answers_a = [answers_a] # Ensure it's a list
            for ans_ip in answers_a:
                if ans_ip and isinstance(ans_ip, str) and not is_private_ip(ans_ip):
                    extracted_events.append({
                        **dns_event_info, # Context of the query
                        "ioc_type": IOC_TYPE_IP,
                        "ioc_value": ans_ip,
                        "dns_record_type": "A",
                        "dns_answer_for_query": queried_name
                    })
        
        # AAAA records (IPv6)
        if hasattr(dns_layer, 'aaaa'):
            answers_aaaa = dns_layer.aaaa
            if not isinstance(answers_aaaa, list): answers_aaaa = [answers_aaaa]
            for ans_ip6 in answers_aaaa:
                 if ans_ip6 and isinstance(ans_ip6, str) and not ip_address(ans_ip6).is_link_local and not ip_address(ans_ip6).is_loopback: # Basic IPv6 filtering
                    extracted_events.append({
                        **dns_event_info,
                        "ioc_type": IOC_TYPE_IP, # Could be IOC_TYPE_IPV6 if you distinguish
                        "ioc_value": ans_ip6,
                        "dns_record_type": "AAAA",
                        "dns_answer_for_query": queried_name
                    })

        # CNAME records
        if hasattr(dns_layer, 'cname'):
            cnames = dns_layer.cname
            if not isinstance(cnames, list): cnames = [cnames]
            for cname_val in cnames:
                if cname_val and isinstance(cname_val, str):
                    extracted_events.append({
                        **dns_event_info,
                        "ioc_type": IOC_TYPE_DOMAIN,
                        "ioc_value": cname_val,
                        "dns_record_type": "CNAME",
                        "dns_answer_for_query": queried_name
                    })
        # Add more DNS record types (MX, TXT, etc.) if needed.

    # --- HTTP Layer Processing ---
    if hasattr(raw_pyshark_packet, 'http'):
        http_layer = raw_pyshark_packet.http
        http_event_info = {**base_event_info} # Copy base info

        http_host = safe_getattr(http_layer, 'host')
        http_uri = safe_getattr(http_layer, 'request_uri', safe_getattr(http_layer, 'uri')) # 'uri' for older tshark/pyshark
        http_method = safe_getattr(http_layer, 'request_method')
        http_user_agent = safe_getattr(http_layer, 'user_agent')
        http_referrer = safe_getattr(http_layer, 'referer')
        http_status_code = safe_getattr(http_layer, 'response_code')
        content_type = safe_getattr(http_layer, 'content_type')

        if http_method: http_event_info["http_method"] = http_method
        if http_user_agent: http_event_info["http_user_agent"] = http_user_agent
        if http_status_code: http_event_info["http_status_code"] = http_status_code
        if content_type: http_event_info["http_content_type"] = content_type
        
        # IOC: Host (Domain or IP)
        if http_host:
            http_event_info["http_host"] = http_host
            ioc_type = IOC_TYPE_DOMAIN
            is_host_ip = False
            try:
                ip_address(http_host) # Check if host is an IP
                ioc_type = IOC_TYPE_IP
                is_host_ip = True
            except AddressValueError:
                pass # It's likely a domain

            if not (is_host_ip and is_private_ip(http_host)): # Don't log private IP hosts as primary IOCs
                extracted_events.append({
                    **http_event_info,
                    "ioc_type": ioc_type,
                    "ioc_value": http_host
                })

        # IOC: Full URL
        if http_host and http_uri:
            # Determine scheme (pyshark http layer is usually after TLS decryption if any)
            scheme = "http" 
            # If TLS layer was present, it was likely HTTPS.
            # SimpleShark doesn't pass this explicitly, but we can check raw_packet.
            if 'TLS' in raw_pyshark_packet: # or raw_pyshark_packet.highest_layer == 'TLS' or 'SSL'
                scheme = "https"
            elif base_event_info["destination_port"] == 443 or base_event_info["source_port"] == 443 : # Heuristic
                 scheme = "https"

            full_url = f"{scheme}://{http_host}{http_uri}"
            
            # Avoid full URL if host is a private IP
            is_host_private_ip = False
            try:
                if ip_address(http_host).is_private: is_host_private_ip = True
            except AddressValueError: pass

            if not is_host_private_ip:
                extracted_events.append({
                    **http_event_info,
                    "ioc_type": IOC_TYPE_URL,
                    "ioc_value": full_url
                })

        # IOC: Referrer URL
        if http_referrer and "://" in http_referrer: # Basic check if it's a URL
             extracted_events.append({
                **http_event_info,
                "ioc_type": IOC_TYPE_URL,
                "ioc_value": http_referrer,
                "url_type": "http_referrer"
            })
            
    # --- TLS/SSL Layer Processing (SNI specifically) ---
    if hasattr(raw_pyshark_packet, 'tls'):
        tls_layer = raw_pyshark_packet.tls
        tls_event_info = {**base_event_info}

        # SNI (Server Name Indication from Client Hello)
        # Pyshark field name can vary: 'handshake_extensions_server_name', 'handshake.extension.server_name'
        sni_hostname = None
        if hasattr(tls_layer, 'handshake_extensions_server_name'):
            sni_hostname = safe_getattr(tls_layer, 'handshake_extensions_server_name')
        elif hasattr(tls_layer, 'handshake.extension.server_name'): # Check alternative path
            sni_hostname = safe_getattr(tls_layer, 'handshake.extension.server_name')
        
        if sni_hostname:
            tls_event_info["tls_sni_hostname"] = sni_hostname
            extracted_events.append({
                **tls_event_info,
                "ioc_type": IOC_TYPE_DOMAIN,
                "ioc_value": sni_hostname
            })
        # Future: Extract JA3/JA3S if pyshark/tshark is configured for it.
        # ja3 = safe_getattr(tls_layer, 'ja3')
        # ja3s = safe_getattr(tls_layer, 'ja3s')
        # if ja3: tls_event_info["tls_ja3"] = ja3
        # if ja3s: tls_event_info["tls_ja3s"] = ja3s

    # --- Add a generic event if no specific IOCs were extracted but packet is interesting ---
    # This ensures every packet processed by SimpleShark can yield at least one record if desired.
    # However, for ML, you might only want records with clear IOCs.
    # For now, we only add events if specific IOCs are found or for specific protocols.
    # If extracted_events is still empty, but it's e.g. TCP/UDP, we could add a generic connection event.
    if not extracted_events and base_event_info["transport_protocol"] in ["TCP", "UDP"]:
         extracted_events.append({
            **base_event_info,
            "ioc_type": "network_flow_summary", # Generic type
            "ioc_value": f"{src_ip}:{base_event_info['source_port']} <-> {dst_ip}:{base_event_info['destination_port']} ({base_event_info['transport_protocol']})"
        })


    # Deduplicate events (e.g., if an IP was extracted as src_ip and also as HTTP host IP)
    # This basic deduplication is on the exact dict. More sophisticated would be on ioc_value+type+context
    unique_events = []
    seen_events_json = set()
    for event in extracted_events:
        event_json = json.dumps(event, sort_keys=True)
        if event_json not in seen_events_json:
            unique_events.append(event)
            seen_events_json.add(event_json)
            
    return unique_events


# --- Example Usage (Simulating input from SimpleShark) ---
if __name__ == "__main__":
    print("Pyshark IOC & Feature Extractor v1 - Example Usage")

    # This example requires pyshark and a capture file (or live interface access for pyshark)
    # For a self-contained example, we'll create mock pyshark packet objects.
    # In a real scenario, `raw_pyshark_packet` would come from pyshark.FileCapture or LiveCapture.

    # Mocking pyshark packet objects is complex.
    # Instead, let's define how this script would be called with data *from* SimpleShark.

    # Imagine SimpleShark captures a packet and produces:
    sample_packet_data_dict_dns = {
        'timestamp': "18:30:05.123", # SimpleShark's format
        'protocol': 'DNS',
        'src_ip': '192.168.1.100', # Private, won't be an IOC itself unless destination is also private
        'src_port': '54321',
        'dst_ip': '8.8.8.8',     # Public DNS server
        'dst_port': '53',
        'size': 78,
        'info': 'Query: www.example.com' # SimpleShark's info string
    }
    # And the corresponding raw_pyshark_packet object (mocked attributes for demonstration)
    class MockPysharkLayer:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)
    
    class MockPysharkPacketDNS:
        sniff_timestamp = str(time.time()) # Float string
        highest_layer = "DNS"
        def __init__(self):
            self.ip = MockPysharkLayer(src='192.168.1.100', dst='8.8.8.8')
            self.udp = MockPysharkLayer(srcport='54321', dstport='53')
            self.dns = MockPysharkLayer(
                qry_name='www.example.com', 
                qry_type_name='A',
                a=['1.2.3.4', '1.2.3.5'] # Example A records
            )
        def __contains__(self, item): # To make 'TLS' in raw_pyshark_packet work
            return hasattr(self, item.lower())


    sample_raw_packet_dns = MockPysharkPacketDNS()
    
    print("\n--- Processing Sample DNS Packet ---")
    extracted_dns_info = extract_info_from_pyshark_packet(sample_packet_data_dict_dns, sample_raw_packet_dns)
    for item in extracted_dns_info:
        print(json.dumps(item, indent=2))

    # --- Sample HTTP Packet ---
    sample_packet_data_dict_http = {
        'timestamp': "18:31:00.500",
        'protocol': 'HTTP',
        'src_ip': '192.168.1.101',
        'src_port': '50000',
        'dst_ip': '93.184.216.34', # example.com
        'dst_port': '80',
        'size': 450,
        'info': 'GET example.com /index.html'
    }
    class MockPysharkPacketHTTP:
        sniff_timestamp = str(time.time())
        highest_layer = "HTTP"
        def __init__(self):
            self.ip = MockPysharkLayer(src='192.168.1.101', dst='93.184.216.34')
            self.tcp = MockPysharkLayer(srcport='50000', dstport='80')
            self.http = MockPysharkLayer(
                host='example.com',
                request_uri='/index.html',
                request_method='GET',
                user_agent='TestBrowser/1.0',
                referer='http://somesite.com/link'
            )
        def __contains__(self, item):
            return hasattr(self, item.lower())

    sample_raw_packet_http = MockPysharkPacketHTTP()

    print("\n--- Processing Sample HTTP Packet ---")
    extracted_http_info = extract_info_from_pyshark_packet(sample_packet_data_dict_http, sample_raw_packet_http)
    for item in extracted_http_info:
        print(json.dumps(item, indent=2))

    # --- Sample TLS Packet (SNI) ---
    sample_packet_data_dict_tls = {
        'timestamp': "18:32:00.700",
        'protocol': 'TLS', # SimpleShark might report TLS as highest layer before full HTTP dissection
        'src_ip': '192.168.1.102',
        'src_port': '50001',
        'dst_ip': '104.18.30.100', # Some CDN IP
        'dst_port': '443',
        'size': 200,
        'info': 'Client Hello' # SimpleShark's info might be generic for TLS
    }
    class MockPysharkPacketTLS:
        sniff_timestamp = str(time.time())
        highest_layer = "TLS" # Or SSL for older versions
        def __init__(self):
            self.ip = MockPysharkLayer(src='192.168.1.102', dst='104.18.30.100')
            self.tcp = MockPysharkLayer(srcport='50001', dstport='443')
            self.tls = MockPysharkLayer(
                handshake_extensions_server_name='secure.example.com'
            )
        def __contains__(self, item):
            return hasattr(self, item.lower())
            
    sample_raw_packet_tls = MockPysharkPacketTLS()
    print("\n--- Processing Sample TLS Packet (for SNI) ---")
    extracted_tls_info = extract_info_from_pyshark_packet(sample_packet_data_dict_tls, sample_raw_packet_tls)
    for item in extracted_tls_info:
        print(json.dumps(item, indent=2))