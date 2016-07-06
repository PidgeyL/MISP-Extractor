#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# MISP Database Command Manager
# Manipulates the commands in the database 
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Default Imports
import argparse
import os
import sys

_runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(_runPath, ".."))

from lib.MispDataManager import MispDataManager

if __name__ == '__main__':
  ap = argparse.ArgumentParser(description='Manipulate commands stored in the database')
  ap.add_argument("db" , metavar="file",     type=str, help='The database to store the information')
  ap.add_argument('-a',  action="store_true",          help='Add a command')
  ap.add_argument('-d',  action="store_true",          help='Drop all commands')
  ap.add_argument('-c',  metavar="command",  type=str, help='The command to be added')
  ap.add_argument('-t',  metavar="datatype", type=str, help='Datatype for the command to apply to (see documentation)')
  ap.add_argument('-s',  metavar="dataset",  type=str, help='Dataset for the command to apply to (all|old|new)')

  args = ap.parse_args()

  if not os.path.isfile(args.db):
    sys.exit("Wrong path for your database")

  if args.d:
    manager = MispDataManager(args.db)
    manager.db.dropCommands()
  elif args.a:
    if not (args.c and args.s and args.t):
      sys.exit("Requires -c -t and -s")
    if args.s.lower() not in ["all", "old", "new"]:
      sys.exit("Wrong dataset")
    manager = MispDataManager(args.db)
    manager.db.addCommand(args.t.lower(), args.c, args.s.lower())
  else:
    sys.exit("Chosose -a to add and -d to drop commands")
