# NETSENTRY -- NETWORK TRAFFIC ANALYZER AND SUSPICIOUS ACTIVITY DETECTION SYSTEM

NETSENTRY is a Python-based network traffic analysis project that
examines previously captured network packets from **PCAP** and
**PCAPNG** files. It applies predefined rules to identify potentially
suspicious traffic patterns and generates a graphical dashboard and a
text report.

## Features

-   Analyze network packets from PCAP and PCAPNG files.
-   Count packets by IPv4 source address.
-   Detect configured suspicious patterns:
    -   High traffic volume
    -   TCP port scanning
    -   TCP SYN flood patterns
    -   ICMP flood patterns
-   Optionally include relevant Wireshark display filters and
    explanations in the report.
-   Generate a graphical traffic dashboard as a PNG image.
-   Generate a timestamped text report.

## Technologies Used

-   **Python** -- main programming language
-   **PyShark** -- reads and analyzes packet captures
-   **Wireshark / TShark** -- packet analysis engine used by PyShark
-   **Matplotlib** -- creates the graphical dashboard
-   **PCAP / PCAPNG** -- input capture formats

## Requirements

1.  Python 3.9 or later (use a Python version supported by your
    installed PyShark and Matplotlib releases).
2.  Wireshark installed, including the TShark command-line utility.
3.  Python packages listed in `requirements.txt`.

## Installation

Clone this repository:

``` bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
cd YOUR-REPOSITORY
```

Create and activate a virtual environment (recommended):

``` bash
python -m venv .venv
```

Windows:

``` bash
.venv\Scripts\activate
```

macOS / Linux:

``` bash
source .venv/bin/activate
```

Install the Python dependencies:

``` bash
python -m pip install -r requirements.txt
```

Install Wireshark and make sure TShark is available on your system PATH.
You can verify the installation with:

``` bash
tshark --version
```

## Run the Project

Start the application:

``` bash
python netsentry.py
```

When prompted, enter the full path to a `.pcap` or `.pcapng` file.

Example path on Windows:

``` text
C:\Users\YourName\Downloads\capture.pcap
```

The application saves the graphical dashboard and timestamped text
report in the same directory as `netsentry.py`.

## Detection Rules

The current implementation uses fixed thresholds:

  -----------------------------------------------------------------------
  Detection                           Current rule
  ----------------------------------- -----------------------------------
  High traffic volume                 More than 200 IPv4 packets from one
                                      source IP

  Port scanning                       More than 25 distinct TCP
                                      destination ports from one source
                                      IP

  SYN flood pattern                   More than 100 TCP SYN packets
                                      without ACK from one source IP

  ICMP flood pattern                  More than 50 ICMP packets from one
                                      source IP
  -----------------------------------------------------------------------

These thresholds are configurable in the source code. They are simple
demonstration rules and should be tuned for the network and capture
being analyzed.

## Output

-   `NetSentry_Dashboard.png` -- graphical summary of packet counts,
    flagged IPs, alerts, traffic over time, and recent findings.
-   `NetSentry_Report_YYYYMMDD_HHMMSS.txt` -- timestamped analysis
    report with detected activity and, optionally, Wireshark filters.

## Important Notes and Limitations

-   NETSENTRY currently analyzes **offline capture files**. It does not
    perform live network monitoring.
-   Detection is rule-based; the project does not currently use machine
    learning or AI.
-   An alert means a traffic pattern crossed a configured threshold. It
    does not prove that an attack occurred.
-   The current implementation focuses on IPv4 traffic.
-   Thresholds are applied across the full capture and are not
    normalized by capture duration or a learned baseline.
-   Port scanning detection counts distinct TCP destination ports per
    source IP across the capture. This can produce false positives in
    some environments.
-   Use packet captures only when you have permission to access and
    analyze them. Captures may contain sensitive information.

## Project Structure

``` text
NETSENTRY/
├── netsentry.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Future Enhancements

-   Live packet monitoring
-   Time-window-based detection and configurable thresholds
-   Improved alert validation and false-positive reduction
-   Interactive web dashboard
-   IP reputation enrichment
-   Optional anomaly detection using machine learning

## License

No license has been specified yet. 
