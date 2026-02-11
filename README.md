# AbuseIPDB Bulk Lookup Tool

A Python-based utility to perform bulk IP address lookups against AbuseIPDB. It extracts IP addresses from various file formats (.csv, .xlsx, .xls, .txt) and generates individual Excel reports with detailed geolocation and reputation data.

## Features
- **Multi-format Support**: Processes `.csv`, `.xlsx`, `.xls`, and `.txt` files.
- **Bulk Processing**: Automatically discovers all supported files in a specified folder.
- **Detailed Data**: Fetches City, State/Region, Country, ISP, Usage Type, and Abuse Confidence Score.
- **Robust Extraction**: Uses regex to find IP addresses even in unstructured text or unnamed Excel columns.
- **Safety First**: Includes SSL verification fallback and rate-limit handling.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/San2506/abuseipdb_lookup.git
   cd abuseipdb_lookup
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the script:
   ```bash
   python abuseipdb_bulk_lookup.py
   ```
2. Enter the folder path containing your input files when prompted.
3. Enter your AbuseIPDB API Key.

## Output
The tool generates an individual Excel report for each input file in the same directory, named `Report_[OriginalFileName]_[Timestamp].xlsx`.

## License
MIT
