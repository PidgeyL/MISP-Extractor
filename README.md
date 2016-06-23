#   MISP-Extractor
Allows users to extract information from MISP using the API.

**Compatible with python 2 and 3**

##  Installation
To install the dependencies, run `pip install -r requirements.txt` for python2, and `pip3 install -r requirements.txt` for python3

For ease of use, you can either put your MISP url and key in the script (hard coded), or add them to your environment variables (`misp_key` and `misp_url`). If you don't want to, you can pass them to the script with `-u` (URL), `-k` (key)

##  Usage
### Extract info
Using the `-d` tag, you can extract the following information with this script:

 * **domains**   - Malicious domains and IP addresses
 * **hashes**    - Hashes of payloads and artifacts of malicious code
 * **filenames** - Names of malicious files
 * **snort**     - Snort rules to help identify malicious behavior
 * **yara**      - Yara rules to help identify malicious behavior

### Filters
Using the `-A` tag, you can filter on analysis level (0: Initial, 1: Ongoing, 2: Completed)

Using the `-T` tag, you can filter on threat level (4: Undefined, 3: Low, 2: Medium, 1: High)

By default, the data is only 5 days old. You can manipulate this using the `-s` tag. You can use (m)inutes, (h)ours, (d)ays or "all" for all data.

### Output
By default the script outputs to `stdout`. Using the `-o` tag, you can output to a file. The format is CSV, and the separator by default is `,`. You can change the separator by using the `-S` tag. By default, there are no headers to the output. If you want to add them, use the `-H` tag.

##  Usecases

 * Check your proxy logs for possible infected machines
 * Check hashes of potentially malicious attachments in mails
 * Analyze your network traffic for suspicious behavior

##  License
This software is licensed under the "Original BSD License".

    (c) 2015  Pieter-Jan Moreels  https://github.com/pidgeyl