import os
import pandas as pd
import re
from abuseipdb_bulk_lookup import get_ips_from_file

def test_extraction():
    test_dir = r'C:\Users\sanhe\.gemini\antigravity\scratch\abuseipdb_lookup\test_inputs'
    
    # Test TXT
    txt_path = os.path.join(test_dir, 'test.txt')
    ips_txt = get_ips_from_file(txt_path)
    print(f"TXT IPs found: {ips_txt}")
    assert '8.8.8.8' in ips_txt
    assert '1.1.1.1' in ips_txt
    assert '127.0.0.1' in ips_txt
    assert '192.168.1.1' in ips_txt
    assert '45.45.45.45' in ips_txt
    assert '999.999.999.999' not in ips_txt
    
    # Test CSV
    csv_path = os.path.join(test_dir, 'test.csv')
    ips_csv = get_ips_from_file(csv_path)
    print(f"CSV IPs found: {ips_csv}")
    assert '8.8.4.4' in ips_csv
    assert '208.67.222.222' in ips_csv
    assert '185.199.110.153' in ips_csv

    print("\nExtraction tests passed!")

if __name__ == "__main__":
    try:
        test_extraction()
    except Exception as e:
        print(f"Test failed: {e}")
