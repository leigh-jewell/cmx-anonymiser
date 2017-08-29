# cmx-anonymiser
---
A Cisco CMX polls Cisco Wireless LAN Controllers for metrics on wireless
clients that are heard by wireless Access Points (APs). Some of this
information such as RSSI and bytes sent/received can be interesting to
use for wireless performance metrics. This program uses the very
versatile CMX API to pull client and AP data, anonymise any personal information
such as mac-address and store the results in csv files for later processing.

## Getting started
---
Simply create a directory and clone the git respository:
git clone https://github.com/leigh-jewell/cmx-anonymiser

This will download two files:
cmx-anonymiser.py - this is the python script that you will run
config.ini - this file contains all the configurable settings for the script

When you run the file it will create two more directories:
output - where the csv files are written to
logs - all the logs from the running of the script

## Prerequisites
---
The script has been written for Python 3 and tested on version 3.6.2. There are
a number of modules which you will need to have installed into your python
installation:

configparser - used to
requests
requests.auth
collections
csv
hashlib
datetime import datetime
os
sched
time

You can simply install them with: pip install <module name>

## Installation and setup
---
The config.ini file contains all the configurable settings to control how
this stript will run.

### Minimum setup
The very minimum changes you will need to make will be to point the script
to your CMX server either by ip address or hostname. The initial config.ini
has the sandbox CMX server that you can use to just test the script out.

cmx_ip = [Change it to your CMX MSE IP address or hostname]

You will need an account created on your CMX MSE so the script can connect
via the API. By default the sandbox username/password has been added so you
can test it out.

username = [username that exists on the CMX]
password = [password for the account on the CMX]

### Optional setup
#### Output
By default the output will be written to the current working directory output
and logs folder. You can change this behaviour to write it somewhere else. You
can also set log_console to tell the script to write logs to the console
if you are testing it out.

output_dir = [default: output]
log_dir = [default: logs]
log_console = [default: True]

#### API
There are two API's which are used and this can be changed to something else.
This is more for if the CMX code is changed and you need to point it to
a new API and perhaps if you want to tweak options. The code is specifically
written to look for a known JSON response. url_clients is to get the current
active clients that the CMX knows about and url_aps gets the current list of
aps.

url_clients = [default: /api/location/v1/clients]
url_aps = [default: /api/config/v1/aps]


#### Schedule
You tell the script how many days and how often you want to poll it. The days is
simply the number of days to poll and hours is a list of 24hr times to
get the data from CMX.

days = [default: 7]
hours = [default: 9:00,12:00,15:00,18:00]

If you put in the string now it will just run the script straight away.

hours = now

### Privacy and anonymisation
Most of the personal information is discarded that is returned from the CMX but
we need to retain the mac-address of the client in some form so we can
connect all the returned data to the same client. To avoid any personal
information from been collected the mac-address is converted to a one-way hash
using SHA256. To avoid collisions and ensure the mac-address remains private
a salt is also added to the string. This can ensure that if you give out
the CSV files to a 3rd party that they can't simply brute force the mac
easily. Obviously keep the salt private when sharing the CSV file. The salt
is just a string so make it whatever you want.
salt = b1e6a4485008303114888c11e7944918

## Running a test
---
Even without changing the config.ini you can test out the code. The config
file is pointing to a Cisco CMX server in a sandbox and as long as this
server is reachable the test should run.

python cmx-anonymiser.py

If console logging is enabled you will see the output on the console as it
pulls down the data and writes the csv files.

Example output:
$ python cmx-anonymiser.py
29/08/17 10:57.44.138577: main: Process started, scheduling jobs 7 days and now hours
29/08/17 10:57.44.166156: getData: Process woken up.
29/08/17 10:57.44.167660: getData:Using CMX:cmxlocationsandbox.cisco.com and username:learning
29/08/17 10:57.44.169164: getCMXAPData: Getting data for: http://cmxlocationsandbox.cisco.com/api/config/v1/aps
29/08/17 10:57.46.298581: getCMXAPData: Got status code 200 from CMX API (200 is good)
29/08/17 10:57.46.298581: getCMXAPData: Got 9 ap records from CMX.
29/08/17 10:57.46.298581: writeFile:Using output as output directory
29/08/17 10:57.46.333839: writeFile:Finished writing.
29/08/17 10:57.46.336848: getCMXData: Getting data for:http://cmxlocationsandbox.cisco.com/api/location/v1/clients
29/08/17 10:57.51.102041: getCMXData: Got status code 200 from CMX API (200 is good)
29/08/17 10:57.51.120462: getCMXData: Got 79 records from CMX.
29/08/17 10:57.51.120462: writeFile:Using output as output directory
29/08/17 10:57.51.149306: writeFile:Finished writing.
29/08/17 10:57.51.151312: getData: Process sleeping.
29/08/17 10:57.51.152316: main: Finished scheduled runs.

### Output CSV files
---
Refer to the CMX API for details on what each field represents:
[CMX API 10.3 ref](https://www.cisco.com/c/en/us/td/docs/wireless/mse/10-3/api/b_cmx_103_api_reference/location.html)

#### File: user_data
'''hash = abfc33006cfc08577dbc697540c0dbcd2cd8c962699b422e9d7cb677e537490f9
mapHierarchyString = CiscoCampus>Building 9>IDEAS!>Kistler
floorRefId = 723413320329068650
length = 74.1
width = 39.0
x = 11.29309
y = 69.07972
unit = FEET
currentlyTracked = True
confidenceFactor = 64.0
currentServerTime = 2017-08-29T01:57:48.292+0100
firstLocatedTime = 2017-08-16T16:05:05.953+0100
lastLocatedTime = 2017-08-29T01:57:48.115+0100
maxDetectedRssiApMacAddress = 00:2b:01:00:08:00
band = IEEE_802_11_B
rssi = -52
lastHeardInSeconds = 0
networkStatus = ACTIVE
changedOn = 1503968268115
ssId = test
band = IEEE_802_11_B
apMacAddress = 00:2b:01:00:08:00
dot11Status = ASSOCIATED
manufacturer = Trw
detectingControllers = 10.10.20.90
bytesSent = 110
bytesReceived = 100
'''
#### File: ap_data
'''
radioMacAddress = 00:2b:01:00:08:00
name = T1-7
x = 3.5704226
y = 69.43445
unit = FEET
802_11_BChannelNumber = 1
802_11_BTxPowerLevel = 1
802_11_AChannelNumber = 64
802_11_ATxPowerLevel = 5
floorId = 723413320329068650
'''
---
### Authors
Leigh Jewell

### License
This project is licensed under the MIT License - see the LICENSE.md file for details

### Acknowledgments
Thanks to Cisco DevNet for their CMX sample code repository:
https://github.com/CiscoDevNet/sample-code-cmx
