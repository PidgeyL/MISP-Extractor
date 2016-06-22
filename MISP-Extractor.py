
# Default Imports
import csv
import json
import sys

from io import StringIO

# External packages
from pymisp import PyMISP

# Set Variables
url = ""
key = ""
searches = {"domains":   [("Network activity",     "domain"  ),
                          ("Network activity",     "hostname"),
                          ("Network activity",     "uri"     ),
                          ("Network activity",     "url"     ),
                          ("Network activity",     "ip-dst"  ),
                          ("Network activity",     "ip-src"  )],
            "hashes":    [("Payload delivery",     "md5"     ),
                          ("Payload delivery",     "sha1"    ),
                          ("Payload delivery",     "sha256"  ),
                          ("Payload installation", "md5"     ),
                          ("Payload installation", "sha1"    ),
                          ("Payload installation", "sha256"  ),
                          ("Artifacts dropped"   , "md5"     ),
                          ("Artifacts dropped"   , "sha1"    ),
                          ("Artifacts dropped"   , "sha256"  )],
            "filenames": [("Payload installation", "filename")],
            "snort":     [("Network activity",     "snort"   )],
            "yara":      [("Payload delivery",     "yara"    ),
                          ("Payload installation", "yara"    )]}

def _generateCSV(output):
  # Make CSV in memory
  memoryFile = StringIO()
  sep = args.S if args.S else ","
  csv_file = csv.writer(memoryFile, delimiter=sep, quotechar='"')
  # Add header if requested
  if args.H:
    csv_file.writerow(["Category", "Type", "Value"])
  # Make CSV file
  for line in output:
    csv_file.writerow(line)
  return memoryFile.getvalue()

def _output(data):
  if args.o:
    with open(args.o, "w") as w:
      w.write(data)
  else:
    print(data)
    
def getMISPData(url, key):
  # Connect to your MISP API 
  misp = PyMISP(url, key, True, 'json')
  since = args.s if args.s else "5d"
  if since.lower() == "all": since = "" 
  misp_last = misp.download_last(since)
  # Verify output
  if 'message' in misp_last.keys():
    if misp_last['message'].lower().startswith('no matches'):
      return [] # No output
    elif misp_last['message'].startswith('Authentication failed.'):
      sys.exit("[-] MISP Authentication failed")
  if not 'response' in misp_last:
    sys.exit("[-] Error occured while fetching MISP data")
  return misp_last['response']

def extractData(entries, to_extract):
  matches = []
  for entry in entries:
    attrs=entry['Event']['Attribute']
    for attr in attrs:
      for test in to_extract:
        if attr["category"] == test[0] and attr["type"] == test[1]:
          matches.append([test[0], test[1], attr["value"]])
  return matches

def getExample(entries):
  a = 0
  for entry in entries:
    if a > 1:
      continue
    a += 1
    with open("example", "w") as w:
      w.write(json.dumps(entry, indent="  "))
      sys.exit()

def getTypes(entries):
  types={}
  for entry in entries:
    attrs=entry['Event']['Attribute']
    for attr in attrs:
      aType = repr((attr["category"], attr["type"]))
      if not aType in types.keys(): types[aType] = attr["value"]
  return types

if __name__ == '__main__':
  import argparse
  argParser = argparse.ArgumentParser(description='Management interface for adding and deleting users from collaboration groups')
  argParser.add_argument('-s', metavar="Since",     type=str,            help='Max age of the data (ex. 5m, 3h, 7d) "all" will return all')
  argParser.add_argument('-d', metavar="Data type", type=str,            help='Data to look for (domains|hashes|filenames|snort|yara)')
  argParser.add_argument('-t',                      action="store_true", help='Get DataTypes (Debug option')
  argParser.add_argument('-o', metavar="file",      type=str,            help='Output file (default stdout)')
  argParser.add_argument('-H',                      action="store_true", help='Include headers to the output')
  argParser.add_argument('-S', metavar="separator", type=str,            help='Separator for the output (default ",")')
  args = argParser.parse_args()

  data = getMISPData(url, key)
  
  if args.t:
    import json
    print(json.dumps(getTypes(data), indent=2, sort_keys=True))
  elif args.d:
    search = args.d.lower()
    if search not in searches.keys():
      sys.exit("Please use a valid search term")
    matches = extractData(data, searches[search])
    output  = _generateCSV(matches)
    _output(output)
