#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Wrapper to check MISP information with proxy logs, based on commands.
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Default Imports
import calendar
import os
import sqlite3
import sys
import time

_runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(_runPath, ".."))

from lib.MispDataManager import MispDataManager

if __name__ == '__main__':
  import argparse
  ap = argparse.ArgumentParser(description='Store a certain amount of information in a local database and execute commands based on this information')
  ap.add_argument("db", metavar="file",      type=str, help='The database to store the information')
  ap.add_argument('-l', metavar="Since",     type=str, help='Max age of the data (ex. 5m, 3h, 7d) to be stored in the database')
  ap.add_argument('-d', metavar="Data type", type=str, help='Data to look for (domains|hashes|filenames|snort|yara)')
  ap.add_argument('-u', metavar="MISP URL",  type=str, help='The URL to the MISP API')
  ap.add_argument('-k', metavar="MISP Key",  type=str, help='Your API key for the MISP API')
  ap.add_argument('-U', action ="store_true",          help='Update only, do not execute commands')
  ap.add_argument('-C', action ="store_true",          help='Create only, do not pull data in the new DB')
  ap.add_argument('-A', metavar="integer",   type=int, help='Analysis level (0: Initial, 1: Ongoing, 2: Completed)')
  ap.add_argument('-T', metavar="integer",   type=int, help='Threat level (4: Undefined, 3: Low, 2: Medium, 1: High)')
  args = ap.parse_args()
  
  if args.l and args.d:
    if os.path.isfile(args.db):
      sys.exit("A file with that name already exists!")
    # Create DB
    manager = MispDataManager(args.db, args.d, args.l, args.k, args.u,
                              args.A,  args.T)
    if args.C:
      sys.exit()
  elif os.path.isfile(args.db):
    manager = MispDataManager(args.db)
  else:
    argParser.print_help()
    sys.exit()
  manager.fetchAndStoreData()
  if not args.U:
    manager.execCommandsOnData("old")
    manager.execCommandsOnData("new")
    manager.execCommandsOnData("all")
