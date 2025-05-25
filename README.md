# Python for Cybersecurity Professionals

In the contemporary cybersecurity landscape, Security Operations Centers (SOCs) are confronted with an ever-increasing volume and sophistication of threats. To effectively manage this deluge of data, detect malicious activities, and respond swiftly to incidents, automation has become indispensable. Python, with its straightforward syntax, extensive libraries, and versatile capabilities, has emerged as a pivotal programming language for cybersecurity professionals, particularly within SOC environments. Its accessibility allows analysts who may not be dedicated software developers to create powerful tools, while its comprehensive standard library and rich ecosystem of third-party packages provide the means to tackle complex security challenges.

## SimpleExtractor - IOC Extractor from Unstructured Text

SOC analysts frequently encounter IOCs—such as IP addresses, domain names, file hashes, and URLs—embedded within unstructured text sources. These sources can include threat intelligence reports, security blogs, forum discussions, social media posts, or even internal incident notes. Manually sifting through large volumes of text to identify and extract these IOCs is a time-consuming, error-prone, and often tedious task. An automated IOC extractor script significantly streamlines this process, enabling analysts to quickly gather potential threat indicators for further investigation, enrichment, or input into security tools like SIEMs or TIPs. This automation frees up valuable analyst time, allowing them to focus on higher-value analytical tasks rather than manual data extraction. The ability to rapidly process diverse textual data for IOCs is crucial for maintaining situational awareness and responding effectively to emerging threats.

Packages required: iocextract ioc-finder yara-python

Capabilities: BTC addresses, email addresses, IPs, CVEs, domains, skype usernames, and more. (Read package documentation for complete list.)

YARA Rules: The script includes a basic YARA rule (example_rule) that looks for the string "malicious" in the text. You can expand this by loading your own YARA rule files or defining more complex rules. Feel free to modify the YARA rules or add more IOC extraction methods as needed.

## SimpleShark - Network Traffic Analyzer

SimpleShark is an advanced, user-friendly network analyzer for Windows, macOS, and Linux that enables real-time monitoring and analysis of network traffic. Designed for IT professionals, security analysts, and enthusiasts, SimpleShark captures and displays live packet data, visualizes protocol usage, identifies top talkers and rare protocols, and tracks sessions between network endpoints. Integrated threat intelligence feeds (Spamhaus, OpenPhish, PhishTank, AbuseIPDB) provide instant detection of suspicious activity, while IP geolocation offers additional context for network events.

With a modern, tabbed graphical interface, SimpleShark allows users to filter protocols, view detailed packet breakdowns, monitor system resource usage, and quickly export comprehensive logs for further analysis. The application is highly configurable, supports multi-sheet Excel reporting, and delivers deep insights into network behavior—all in an accessible, attractive package.

Packages required: pyshark, tkinter, psutil, matplotlib, cartopy, geoip2, requests, pandas, openpyxl, and ipwhois

## SimpleThreatAggregator

SimpleThreatAggregator is a comprehensive, open-source threat intelligence platform built with Python and PyQt6 that automates the collection, analysis, and visualization of cybersecurity threat data from multiple sources. The application aggregates Indicators of Compromise (IOCs) from leading threat intelligence providers including VirusTotal, GreyNoise, AbuseIPDB, AlienVault OTX, MISP, and URLhaus, while also collecting Common Vulnerabilities and Exposures (CVE) data from NIST NVD and GitHub Security Advisories. It features an intuitive tabbed GUI interface for configuration management, real-time status monitoring, and interactive data visualization, along with robust SQLite database storage, REST API endpoints, and comprehensive export capabilities for CSV and machine learning feature extraction.

The platform is designed for cybersecurity professionals, threat hunters, and security researchers who need to centralize threat intelligence feeds into a single, manageable interface. With its asynchronous data collection engine, built-in rate limiting, and modular provider architecture, SimpleThreatAggregator can scale from individual research projects to enterprise-level threat intelligence operations. The application includes advanced features such as threat scoring algorithms, temporal analysis, data correlation capabilities, and seamless integration options through its REST API, making it an essential tool for proactive threat detection and security analytics workflows.

Packages required: PyQt6 httpx pandas matplotlib fastapi uvicorn sqlite3

## Splunk Custom Alert Actions/Enrichment Script

Splunk is a cornerstone of many SOCs for log aggregation, searching, and alerting. While Splunk's built-in alerting capabilities are robust, Python scripts can extend them significantly by enabling custom alert actions and automated enrichment of alert data. Instead of an alert merely triggering an email or a ticket, a custom Python script can execute a complex workflow. This could involve querying external threat intelligence feeds for IOCs found in the alert, checking internal asset databases for system ownership, looking up WHOIS information for suspicious domains, or even initiating automated responses like adding an IP to a firewall blocklist via an API. The splunk-alert-script found in the Splunk-Automation-Tools repository, which polls the Splunk API to generate alerts from search results, exemplifies a form of custom alerting logic. Such scripts transform raw alerts into more context-rich and actionable intelligence.

## Automated IOC Reputation Checker (via VirusTotal API)

 fundamental task in SOC operations is assessing the risk associated with Indicators of Compromise (IOCs) such as IP addresses, domain names, URLs, or file hashes. Manually checking each IOC against various threat intelligence sources is inefficient, especially when dealing with multiple indicators from an alert or investigation. An automated IOC reputation checker script, typically leveraging APIs from services like VirusTotal, streamlines this process significantly. It provides analysts with quick, consolidated insights into whether an IOC is known malicious, suspicious, or benign, which is crucial for prioritizing alerts, guiding incident response efforts, and making informed decisions about potential threats. This script can be used ad-hoc by analysts or integrated into other automated workflows, such as the Splunk custom alert action script (Script 3) or after IOC extraction (Script 1).

 ## Suspicious Email Analyzer (EML Parser)

 Email remains a primary vector for cyberattacks, including phishing, malware distribution, and business email compromise. SOCs often receive suspicious emails reported by users (e.g., via a phish-button) or quarantined by email security gateways, typically in the .eml (email message) format. Manually analyzing each .eml file to extract headers, body content, links, and attachments is highly time-consuming and requires specialized knowledge. A Python script designed to parse .eml files automates this initial triage, extracting key indicators and metadata. This allows analysts to quickly assess the potential threat posed by an email, identify actionable IOCs, and decide whether further in-depth investigation, escalation, or blocking actions are warranted. Scripts like meioc (Mail Extractor IoC) are specifically built for this purpose, providing a structured output of extracted information.

## Locate Executable Files with Python

This project entails the construction of a Python script to effectively locate .exe files across a computer's filesystem. The solution leverages the standard os and os.path modules, employing os.walk for efficient recursive directory traversal and os.path.splitext for accurate file extension identification. Key considerations for robustness include platform-independent path construction using os.path.join and comprehensive error handling using both try...except blocks within the processing loop and the onerror callback for os.walk to manage permissions issues gracefully.

The definition of the search scope (the root directories) is critical. While specific paths can be provided manually, the third-party psutil library offers a cross-platform method for programmatically discovering potential starting points (drives/mount points), although careful filtering is often required for practical application. The final script presented integrates these components, providing a functional and adaptable tool for filesystem searching. The alternatives using pathlib or glob offer different syntaxes but generally less control over the traversal and error handling compared to the os.walk-based approach detailed herein.
