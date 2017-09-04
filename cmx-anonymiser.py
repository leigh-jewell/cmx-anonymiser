# Author Leigh Jewell
# License https://github.com/leigh-jewell/cmx-anonymiser/blob/master/LICENSE
# Github repository: https://github.com/leigh-jewell/cmx-anonymiser

# Try and load in all the required modules.
try:
    import sys
    import configparser
    import requests
    # Ignore HTTPS warnings if they appear
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    from requests.auth import HTTPBasicAuth
    from collections import defaultdict
    import csv
    import hashlib
    from datetime import datetime
    from datetime import timedelta
    import os
    import sched, time
except ImportError:
    print('Error: Missing one of the required modules. Check the docs.')
    sys.exit()

#Constants
# CMX API URL prefix, could be changed to https://
url_prefix = "http://"

#Read configuration from config.ini file into global variables
#Expects to find is in the same directory as the program file
config = configparser.ConfigParser()
if os.path.isfile("config.ini"):
    try:
        config.read("config.ini")
        cmx = config.get('cmx', 'cmx_ip')
        username = config.get('cmx', 'username')
        password = config.get('cmx', 'password')
        timeout = config.get('cmx', 'timeout', fallback=4)
        timeout = int(timeout)
        max_retries = config.get('cmx', 'retry', fallback=5)
        max_retries = int(max_retries)
        sleep_between_retries = config.get('cmx', 'retry_sleep', fallback=3)
        sleep_between_retries = int(sleep_between_retries)
        url_clients = config.get('cmx', 'url_clients', fallback="/api/location/v1/clients/")
        url_aps = config.get('cmx', 'url_aps', fallback="/api/config/v1/aps/")
        output_dir = config.get('output', 'output_dir', fallback=os.path.join(os.getcwd(), 'output'))
        log_dir = config.get('output', 'log_dir', fallback=os.path.join(os.getcwd(), 'logs'))
        log_console = config.getboolean('output', 'log_console', fallback=False)
        days = config.get('schedule', 'days', fallback=5)
        days = int(days)
        schedule = config.get('schedule', 'hours', fallback='9:00,12:00,15:00,18:00')
        salt = config.get('privacy', 'salt', fallback='b1303114888c11e79e6a448500844918')
        configError = False
    except configparser.Error as e:
        print("Error with config.ini, missing part of the file: ", e)
        configError = True
else:
    print("config.ini missing from current directory.")
    configError = True

# Setup the path and filename for the log file
if not os.path.exists(log_dir):
    try:
        os.makedirs(log_dir)
    except OSError as e:
        print('Error - log directory {} does not exist, and cannot create it {}'.format(log_dir, e))
    # Create a unique file name by appending the date to the end
logFile = 'cmx' + datetime.strftime(datetime.now(),'-%d-%m-%y-%H-%M.log')
fulllogFile = os.path.join(log_dir, logFile)

def logging(info):
    # Setup logging to a file and console
    # Create a unique name with the date and time
    dateStamp = datetime.strftime(datetime.now(),'%d/%m/%y %H:%M.%S.%f: ') + info
    if log_console:
        print(dateStamp)
    try:
        with open(fulllogFile,'a', newline='\n', encoding='utf-8') as f:
            print(dateStamp, file=f)
    except OSError as e:
        print('Error - tried to open file for writing but something went wront {}'.format(e))
    return

def deidentifyMac(mac):
    # Take the mac-address and deidentify it by securely hashing it
    # Add the salt to the mac and encode before hashing result and then returning the unique token
    mac_hashed = hashlib.sha256(salt.encode()+mac.encode()).hexdigest()
    return mac_hashed

def requestCMX(URL, response_dict):
    # Generic API call to CMX with all the error handling
    no_data = True
    number_retries = 1
    response = requests.Session()
    while no_data and number_retries <= max_retries:
        logging("getData: Attempting to request data  from cmx. Attempt number {}".format(number_retries))
        try:
            response = requests.get(url = URL, auth = HTTPBasicAuth(username, password), verify=False, timeout=timeout)
            if response.status_code == 200:
                no_data = False
                response_dict['isError'] = False
        except requests.exceptions.ConnectionError as e:
            e = str(e)
            logging("getData: Got connectError from URL requests\n"+e)
            response_dict['isError'] = True
            time.sleep(sleep_between_retries)
        except requests.exceptions.HTTPError as e:
            e = str(e)
            logging("getData: Got HTTPError from URL requests\n"+e)
            response_dict['isError'] = True
            time.sleep(sleep_between_retries)
        except requests.exceptions.ConnectTimeout as e:
            e = str(e)
            logging("getData: Got connectTimeout from URL requests\n"+e)
            response_dict['isError'] = True
            time.sleep(sleep_between_retries)
        except requests.exceptions.RequestException as e:
            e = str(e)
            logging("getData: Got general error RequestException from URL requests\n"+e)
            response_dict['isError'] = True
            time.sleep(sleep_between_retries)
        number_retries += 1

    return [response, response_dict]

def getCMXData():
    # API call to get the client data from the CMX
    URL = url_prefix + cmx + url_clients
    logging('getCMXData: Getting data for:{}'.format(URL))
    # Setup a defaultdict so we can reference keys without errors
    response_dict = defaultdict(list)
    response, response_dict = requestCMX(URL, response_dict)
    if not response_dict['isError']:
        # Check the status code of the result to see if we got something
        logging('getCMXData: Got status code {} from CMX API (200 is good)'.format(response.status_code))
        response_dict['statusCode'] = response.status_code
        if response.status_code == 200:
            response.encoding = 'utf-8'
            # Add a header for all the variables
            response_dict['data'].append(['hash',
                                         'mapHierarchyString',
                                          'floorRefId',
                                          'length',
                                          'width',
                                          'x',
                                          'y',
                                          'unit',
                                          'currentlyTracked',
                                          'confidenceFactor',
                                          'currentServerTime',
                                          'firstLocatedTime',
                                          'lastLocatedTime',
                                          'maxDetectedRssiApMacAddress',
                                          'band',
                                          'rssi',
                                          'lastHeardInSeconds',
                                          'networkStatus',
                                          'changedOn',
                                          'ssId',
                                          'band',
                                          'apMacAddress',
                                          'dot11Status',
                                          'manufacturer',
                                          'detectingControllers',
                                          'bytesSent',
                                          'bytesReceived'
                                         ])
            # Step through the JSON response pulling out the data
            for client in response.json():
                response_dict['data'].append([deidentifyMac(client['macAddress']), \
                                              client['mapInfo']['mapHierarchyString'], \
                                              client['mapInfo']['floorRefId'], \
                                              client['mapInfo']['floorDimension']['length'], \
                                              client['mapInfo']['floorDimension']['width'], \
                                              client['mapCoordinate']['x'], \
                                              client['mapCoordinate']['y'], \
                                              client['mapCoordinate']['unit'], \
                                              client['currentlyTracked'], \
                                              client['confidenceFactor'], \
                                              client['statistics']['currentServerTime'], \
                                              client['statistics']['firstLocatedTime'], \
                                              client['statistics']['lastLocatedTime'], \
                                              client['statistics']['maxDetectedRssi']['apMacAddress'], \
                                              client['statistics']['maxDetectedRssi']['band'], \
                                              client['statistics']['maxDetectedRssi']['rssi'], \
                                              client['statistics']['maxDetectedRssi']['lastHeardInSeconds'], \
                                              client['networkStatus'], \
                                              client['changedOn'], \
                                              client['ssId'], \
                                              client['band'], \
                                              client['apMacAddress'], \
                                              client['dot11Status'], \
                                              client['manufacturer'], \
                                              client['detectingControllers'], \
                                              client['bytesSent'], \
                                              client['bytesReceived']
                                             ])
            # We minus 1 due to header that was added to file
            logging('getCMXData: Got {} records from CMX.'.format(len(response_dict['data'])-1))

    return response_dict

def getCMXAPData():
    # Get the AP data from the CMX
    URL = url_prefix + cmx + url_aps
    logging('getCMXAPData: Getting data for: {}'.format(URL))
    response_dict = defaultdict(list)
    response, response_dict = requestCMX(URL, response_dict)
    if not response_dict['isError']:
        logging('getCMXAPData: Got status code {} from CMX API (200 is good)'.format(response.status_code))
        response_dict['statusCode'] = response.status_code
        if response.status_code == 200:
            response.encoding = 'utf-8'
            response_dict['data'].append(['radioMacAddress',
                                          'name',
                                          'x',
                                          'y',
                                          'unit',
                                          '802_11_BChannelNumber',
                                          '802_11_BTxPowerLevel',
                                          '802_11_AChannelNumber',
                                          '802_11_ATxPowerLevel',
                                          'floorId'
                                         ])
            for ap in response.json():
                if len(ap['apInterfaces']) == 2:
                    response_dict['data'].append([ap['radioMacAddress'], \
                                                  ap['name'], \
                                                  ap['mapCoordinates']['x'], \
                                                  ap['mapCoordinates']['y'], \
                                                  ap['mapCoordinates']['unit'], \
                                                  ap['apInterfaces'][0]['channelNumber'], \
                                                  ap['apInterfaces'][0]['txPowerLevel'], \
                                                  ap['apInterfaces'][1]['channelNumber'], \
                                                  ap['apInterfaces'][1]['txPowerLevel'], \
                                                  ap['floorIdString']
                                                 ])
                elif len(ap['apInterfaces']) == 1:
                    response_dict['data'].append([ap['radioMacAddress'], \
                          ap['name'], \
                          ap['mapCoordinates']['x'], \
                          ap['mapCoordinates']['y'], \
                          ap['mapCoordinates']['unit'], \
                          ap['apInterfaces'][0]['channelNumber'], \
                          ap['apInterfaces'][0]['txPowerLevel'], \
                          0, \
                          0, \
                          ap['floorIdString']
                         ])
            logging('getCMXAPData: Got {} ap records from CMX.'.format(len(response_dict['data'])-1))

    return response_dict

def writeFile(data, fileName):
    # Write the data to an appropriate file
    logging('writeFile:Using {} as output directory'.format(output_dir))
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
        except OSError as e:
            logging('writeFile:Error - output directory {} does not exist, and cannot create it {}'.format(output_dir, e))
    if os.path.exists(output_dir):
        # Create a unique file name by appending the date to the end
        fileNameDate = fileName + datetime.strftime(datetime.now(),'-%d-%m-%y-%H-%M-%S-%f.csv')
        fullFileName = os.path.join(output_dir, fileNameDate)
        # Its a new unique file so it shouldn't exist
        if not os.path.isfile(fullFileName):
            try:
                with open(fullFileName,'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerows(data['data'])
                    logging('writeFile:Finished writing.')
            except IOError as e:
                logging('writeFile:Error - tried to open file for writing but something went wront {}'.format(e))
        else:
            logging('writeFile:Error - tried to create unique output file name {} but file exists'.format(fileNameDate))
    else:
        logging('writeFile: problem with output directory.')
    return

def getData():
    # This is the function that gets call by the scheduler
    logging('getData: Process woken up.')
    logging('getData:Using CMX:{} and username:{}'.format(cmx, username))

    ap_data = getCMXAPData()
    if not ap_data['isError']:
        writeFile(ap_data, 'ap_data')
    else:
        logging("getData: getCMXAPData had an error, nothing to write.")
    user_data = getCMXData()
    if not user_data['isError']:
        writeFile(user_data, 'user_data')
    else:
        logging("getData: getCMXData had an error, nothing to write.")

    logging('getData: Process sleeping.')
    return

def main():
    # Make sure we read in the config file ok.
    if not configError:
        logging("main: Process started, scheduling jobs {} days and {} hours".format(days, schedule))
        # If we find now string in schdule we just run one straight away.
        if 'now' in schedule:
            getData()
        else:
            s = sched.scheduler(time.time, time.sleep)
            # Step through all the scheduled 24hr times
            sched_time = [i.split(':') for i in schedule.split(',')]
            # Need current time as scheduler wants to know how many secs to run the function
            today = datetime.now()
            # Step through the days and schedule the getData function to run at the appropriate time.
            for day in range(days):
                for (sched_hour,sched_min) in sched_time:
                    hr = int(sched_hour)
                    minute = int(sched_min)
                    # Need to get correct year month day for days in the future
                    future = datetime.now() + timedelta(days=day)
                    # Create a new date using the scheduled hours and minutes
                    future_date = datetime(future.year, future.month, future.day, hr, minute, 0)
                    # Get the delta between future and todays date and time in seconds so we can schedule
                    secs = (future_date - today).total_seconds()
                    # For time that is in the future schedule the call of the getData function
                    if secs > 0:
                        logging('main: getData will be run {} total secs {}'.format(future_date, secs))
                        s.enter(secs, 1, getData)
            # Allow the scheduler to run schedule the jobs to run.
            s.run()
        logging('main: Finished scheduled runs.')

if __name__ == "__main__":
    main()
