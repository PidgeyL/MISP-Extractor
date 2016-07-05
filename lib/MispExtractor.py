#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Main class to extract data from the MISP API
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com
# Imports
import os
import sys

# External packages
from pymisp import PyMISP

# Class
class MispExtractor():
  # Default Vars
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
  analysis = {0: "Initial",
                   1: "Ongoing",
                   2: "Completed"}
  threat_level = {4: "Undefined",
                       3: "Low",
                       2: "Medium",
                       1: "High"}

  # Functions
  def __init__(self, url=None, key=None):
    self._loadSettings(url, key)

  def _loadSettings(self, url=None, key=None):
    # See if args passed
    if not self.url: self.url = url
    if not self.key: self.key = key
    # Check environment variables
    if not self.url: self.url = os.getenv("misp_url")
    if not self.key: self.key = os.getenv("misp_key")
    # Exit if necessary
    if not self.url: raise Exception("Could not find the MISP API URL")
    if not self.key: raise Exception("Could not find the MISP API key")

  def getMISPData(self, since=None):
    # Connect to your MISP API 
    misp = PyMISP(self.url, self.key, True, 'json')
    since = since if since else "5d"
    if since.lower() == "all": since = "" 
    misp_last = misp.download_last(since)
    # Verify output
    if 'message' in misp_last.keys():
      if misp_last['message'].lower().startswith('no matches'):
        return [] # No output
      elif misp_last['message'].startswith('Authentication failed.'):
        raise Exception("[-] MISP Authentication failed")
    if not 'response' in misp_last:
      raise Exception("[-] Error occured while fetching MISP data")
    return misp_last['response']

  def extractData(self, data, search, threat_level=None,
                                      analysis_level=None):
    to_extract = self.searches[search]
    matches = []
    for entry in data:
      # Skip entries if not valid
      if threat_level and threat_level in threat_level.keys():
        # If the threat is too low, skip
        if threat_level > int(entry["Event"]["threat_level_id"]): continue
      if analysis_level and analysis_level in analysis.keys():
        # If the analysis is not far enough, skip
        if analysis_level < int(entry["Event"]["analysis"]): continue
      # Continue
      attrs=entry['Event']['Attribute']
      for attr in attrs:
        for test in to_extract:
          if attr["category"] == test[0] and attr["type"] == test[1]:
            matches.append([test[0], test[1], attr["value"]])
    return matches

  def getExample(self, entries):
    a = 0
    for entry in entries:
      if a > 1:
        continue
      a += 1
      with open("example", "w") as w:
        w.write(json.dumps(entry, indent="  "))
        sys.exit()

  def getTypes(self, entries):
    types={}
    for entry in entries:
      attrs=entry['Event']['Attribute']
      for attr in attrs:
        aType = repr((attr["category"], attr["type"]))
        if not aType in types.keys(): types[aType] = attr["value"]
    return types
