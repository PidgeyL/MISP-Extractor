import csv
import os
import re
import sys

_runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(_runPath, ".."))

if sys.version_info < (3, 0):
  from io import BytesIO as memIO
else:
  from io import StringIO as memIO

def generateCSV(data, separator = None, header = None):
  # Make CSV in memory
  memoryFile = memIO()
  sep = separator if separator else ","
  csv_file = csv.writer(memoryFile, delimiter=sep, quotechar='"')
  # Add header if requested
  if (header and type(header) is list 
             and all([type(x) == str for x in header])):
    csv_file.writerow(header)
  # Make CSV file
  for line in data:
    if sys.version_info < (3, 0) and isinstance(line[2], unicode):
      line[2] = line[2].encode("unicode-escape")
    csv_file.writerow(line)
  return memoryFile.getvalue()

def toFullPath(path):
  return path if os.path.isabs(path) else os.path.join(_runPath, "..", path)

def lifeSpanToMinutes(lifeSpan):
  split = re.findall('\d+|\D+', lifeSpan)
  try:
    if len(split) > 2 or len(split) == 0:
      raise Exception
    base = int(split[0])
    if len(split) == 1:
      multiplier = 1
    else:
      multiplier = (split[1]).strip().lower()
      if multiplier == "m":   multiplier = 1
      elif multiplier == "h": multiplier = 60
      elif multiplier == "d": multiplier = 60 * 24
      elif multiplier == "w": multiplier = 60 * 24 * 7
  except Exception as e:
    print(e)
    return 1
  return "%sm"%(base * multiplier)
