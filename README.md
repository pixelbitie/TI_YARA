# TI_YARA
Python script that fetches recent threat intel from the ThreatFox API and aggregates them into a usable .yara file.

>[!WARNING]
>Be cautious of running ``cat`` on any of the outputted .yara files, or when reading it in general - it will contain malicious domains.

## Requirements:
Run the following to install dependencies
```bash
  pip install -r requirements.txt
```

## Usage
Execute the script through
```bash
  python TI_YARA.py
```

The outputted file can then be found in ``TI_YARA.py``, relative to where the script was run.
