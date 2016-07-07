#     MISP-Extractor
Allows users to extract information from MISP using the API.

**Compatible with python 2 and 3**

##    Installation
To install the dependencies, run `pip install -r requirements.txt` for
 python2, and `pip3 install -r requirements.txt` for python3

For ease of use, you can either put your MISP url and key in the script
 (hard coded), or add them to your environment variables (`misp_key` and
 `misp_url`). If you don't want to, you can pass them to the script with
 `-u` (URL), `-k` (key)

##    Usage
###   Fetching info
`bin/MISP-Extractor.py`is the main script, that extracts information
 from the MISP API, and saves the output as a CSV file. The output can
 be a file, or stdout.

####  Extract info
Using the `-d` tag, you can extract the following information with this
 script:

 * **domains**   - Malicious domains and IP addresses
 * **hashes**    - Hashes of payloads and artifacts of malicious code
 * **filenames** - Names of malicious files
 * **snort**     - Snort rules to help identify malicious behavior
 * **yara**      - Yara rules to help identify malicious behavior

####  Filters
Using the `-A` tag, you can filter on analysis level (0: Initial, 1:
 Ongoing, 2: Completed)

Using the `-T` tag, you can filter on threat level (4: Undefined, 3:
 Low, 2: Medium, 1: High)

By default, the data is only 5 days old. You can manipulate this using
 the `-s` tag. You can use (m)inutes, (h)ours, (d)ays or "all" for all
 data.

####  Output
By default the script outputs to `stdout`. Using the `-o` tag, you can
 output to a file. The format is CSV, and the separator by default is
 `,`. You can change the separator by using the `-S` tag. By default,
 there are no headers to the output. If you want to add them, use the
 `-H` tag.

###   Automating tasks with MISP data
`sbin/DataManager.py` is a wrapper that stores a specified amount of
 data in a local sqlite database, based on the age of the data (similar
 to the MISP-Extractor). It is able to execute commands, based on the
 type and age of the data, and stores everything in a single database
 file. It is perfect for scheduled tasks, like a daily check of your
 proxy logs against known bad domains.

####  Creating a database
Creating a database exists of two steps: creating the database and
adding commands. The latter is optional. To create the database, call
`sbin/DataManager.py` with parameters `-l` and `-d`, and the path where
you want to create the database.

####  Commands to execute on the data
If you want to execute commands based on the data, you can add commands
to the database using the `sbin/CommandManager.py` script. To add a
command, choose the `-a` option, and specify your command using `-c`,
the datatype with `-t` and the dataset with `-s`. Examples are:

 * `python sbin/CommandManager.py -c "rm /tmp/infected_domains
   /tmp/IPs_responding" -t initial -s new`
 * `python sbin/CommandManager.py -c "echo '%hit%' >>
   /tmp/infected_domains" -t domain -s new`
 * `python sbin/CommandManager.py -c "ping -W 1 -c 1 %hit% | grep 'bytes
   from' | cut -d' ' -f4 | cut -d':' -f1 >> /tmp/IPs_responding" -t
   ip-dst -s all`
 * `python sbin/CommandManager.py -c "python myscript.py
   /tmp/infected_domains" -t final -s new`

**Note:** Currently, we only support one command per type, per set. If
 you have more, the last one will be used. This may be changed in the
 future.

**Note:** Commands of the type `initial` get executed before iterating
 over the data, `final` commands at the end. All others will be run while
 iterating over the data, if the type matches.

**Note:** If you want to only create the database, without pulling the
 data yet, use the `-C` tag

##### Modifiers
The commands will have a certain set of modifiers you can use. The current
 supported modiefiers are:

 * `%hit%`  - gets replaced with the data stored (*e.g. zzzch.zapto.org*)
 * `%type%` - gets replaced with the type of the data (*e.g. hostname*)

####  Using the data
Once your database is ready, run the same script using only the database
 as the argument. `-k` and `-u` are, as with all scripts, optional, if
 you do not have your MISP credentials stored in your environment
 variables. `-U` will only update the data, without running the
 commands.

##    Usecases

 * Check your proxy logs for possible infected machines
 * Check hashes of potentially malicious attachments in mails
 * Analyze your network traffic for suspicious behavior

##    License
This software is licensed under the "Original BSD License".

    (c) 2015  Pieter-Jan Moreels  https://github.com/pidgeyl