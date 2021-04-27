# Modules
import time
import argparse
import traceback

# External modules
import requests
from bs4 import BeautifulSoup

# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",
                    dest="url",
                    help="The Apache server-status URL.",
                    action='store',
                    required=True)
parser.add_argument("--sleeping-time",
                    dest="sleeping_time",
                    help="Sleeping time between each request.\
                    (Default: 10)",
                    action='store',
                    default=10)
parser.add_argument("-o", "--output",
                    dest="output_path",
                    help="Saves output constantly\
                    into a newline-delimited output file.",
                    action='store')
parser.add_argument("--enable-full-logging",
                    dest="enable_full_logging",
                    help="Enable full logging for all requests\
                    with timestamps of each request.",
                    action='store_true',
                    default=False)
parser.add_argument("--debug",
                    dest="enable_debug",
                    help="Shows debugging information\
                    for errors and exceptions",
                    action='store_true',
                    default=False)

args = parser.parse_args()

url = args.url if args.url else ''
sleeping_time = args.sleeping_time if args.sleeping_time else ''
output_path = args.output_path if args.output_path else ''
enable_full_logging = args.enable_full_logging
enable_debug = args.enable_debug

class tcolor:
    """
    A simple coloring class.
    """
    endcolor = '\033[0m'
    red = '\033[31m'
    green = '\033[32m'
    purple = '\033[35m'
    yellow = '\033[93m'
    light_blue = '\033[96m'

def Exception_Handler(e):
    """
    Catches exceptions, and shows it on screen
    when --debug is True.
    """
    global enable_debug
    if enable_debug is True:
        print('%s%s%s' % (tcolor.red, str(e), tcolor.endcolor))
    return(0)

class Request_Handler():
    """
    Handles anything related to requests.
    Manually modify the __init__ variables for customzing.
    """
    def __init__(self):
        self.user_agent = 'server-status-mon @jtcsec'
        self.timeout = '3'
        self.origin_ip = '127.0.0.1'
        self.additional_headers = {}
        # Fill this dict with additional headers if needed.
        # It will work normally by default.

    def send_request(self, url):
        """
        Sends requests.
        """
        headers = {"User-Agent": self.user_agent, 'Accept': '*/*'}
        headers.update(self.additional_headers)

        try:
            req = requests.get(url,
                               headers=headers,
                               timeout=int(self.timeout),
                               verify=False,
                               allow_redirects=False)
            output = str(req.content)
        except Exception as e:
            Exception_Handler(e)
            output = ''
        return(output)

class Response_Handler():
    """
    Handles validation and parsing of response.
    """

    def validate_response(self, response):
        """
        Validates the response, and checks whether the output is valid.
        """
        valid_patterns = ['<h1>Apache Server Status for']
        for pattern in valid_patterns:
            if pattern in response:
                return(True)

        return(False)

    def parse_response(self, response,hostname):
        """
        Parses Apache serve-status response.
        """
        VHOST_List = []
        REQUEST_URI_List = []
        FULL_URL_List = []
        CLIENT_IP_ADDRESS_List = []

        # URL-related.
        soup = BeautifulSoup(response, 'lxml')
        try:
            table_index_id = 0
            VHOST_index_id = -2
            REQUEST_URI_index_id = -1
            CLIENT_IP_ADDRESS_index_id = -3
            mastertable = 0
            tables = soup.findAll("table")
            bigt = ''
            for t in tables:
                tds =  t.findChildren('th')
                for d in tds:
                    #print(d.text)
                    if "VHost" in d.text:
                        table_index_id = mastertable
                        bigt = t
                mastertable += 1
            #print(table_index_id)

            for _ in range(len(bigt.findChildren('tr'))):
                if _ != 0:
                    try:
                        VHOST = bigt.findChildren('tr')[_].findChildren('td')[VHOST_index_id].getText()
                    except Exception as e:
                        Exception_Handler(e)
                        VHOST = ''
                    try:
                        REQUEST_URI = bigt.findChildren('tr')[_].findChildren('td')[REQUEST_URI_index_id].getText().split(' ')[1]
                    except Exception as e:
                        Exception_Handler(e)
                        REQUEST_URI = ''
                    try:
                        if (VHOST == REQUEST_URI == ''):
                            FULL_URL = ''
                        else:
                            FULL_URL = 'https://' + str(VHOST) + str(REQUEST_URI)
                            #resp = requests.get(FULL_URL,verify=False)
                            #if resp.status_code != 200:
                              #  FULL_URL = ''
                    except Exception as e:
                        Exception_Handler(e)
                        FULL_URL = ''
                    pieces = hostname.split("//")
                    hn = pieces[1].split("/")
                    hn1 = hn[0]

                    VHOST_List.append(VHOST)

                    REQUEST_URI_List.append(REQUEST_URI)
                    FULL_URL_List.append(FULL_URL)
                    if FULL_URL != '':
                        FULL_URL_List.append("https://"+hn1+str(REQUEST_URI))
                    # Client-related.
                    try:
                        CLIENT_IP_ADDRESS = bigt.findChildren('tr')[_].findChildren('td')[CLIENT_IP_ADDRESS_index_id].getText()
                    except:
                        CLIENT_IP_ADDRESS = ''

                    CLIENT_IP_ADDRESS_List.append(CLIENT_IP_ADDRESS)

        except Exception as e:
            Exception_Handler(e)
            pass
        output = {"VHOST": VHOST_List, "REQUEST_URI": REQUEST_URI_List, "FULL_URL": FULL_URL_List, "CLIENT_IP_ADDRESS": CLIENT_IP_ADDRESS_List}
        return(output)




def output_to_file(output_data):
    """
    Outputs identified URLs into a newline-delimited file.
    """
    try:
        o_file = open(output_path, 'a')
        o_file.write(str(output_data) + '\n')
        o_file.close()
    except Exception as e:
        print('%s[!] Error writing to file. %s' % (tcolor.red, tcolor.endcolor))
        Exception_Handler(e)
        return(1)
    return(0)

def main(url, full_logging=False):
    observed_ips = []
    observed_vhosts = []
    observed_urls = []
    error_limit = 20
    error_counter = 0
    while True:
        print('%s[#] Requesting. %s' % (tcolor.light_blue, tcolor.endcolor))
        output = Request_Handler().send_request(url)
        validate_output = Response_Handler().validate_response(output)
        if validate_output is not True:
            print('%s[!] Output does not seem to be valid.%s' % (tcolor.red, tcolor.endcolor))
            print('Trying again, feel free to exit [CTRL+C] and debug the issue.')
            Exception_Handler('Output: %s' % (output))
            error_counter = error_counter + 1
            if (error_limit <= error_counter):
                print('%s[!] Too many errors.%s' % (tcolor.red, tcolor.endcolor))
                print('\nExiting...')
                exit(1)
            else:
                pass
        else:
            #print("before parse")
            parsed_output = Response_Handler().parse_response(output,url)
            #print("after parse before loop")
            for _ in range(len(parsed_output['FULL_URL'])):
                #print(parsed_output['FULL_URL'][_])
                if (parsed_output['FULL_URL'][_] not in  observed_urls) and (parsed_output['FULL_URL'][_] != ''):
                    #print("b4 try")
                    try:
                        try:
                           # time.sleep(1)
                            resp = requests.get(parsed_output['FULL_URL'][_],verify=False)
                            if resp.status_code == 200:
                           #     print("Got 200 for url "+parsed_output['FULL_URL'][_])
                                observed_urls.append(parsed_output['FULL_URL'][_])
                                print('%s[New URL]: %s %s%s%s' % (tcolor.yellow, tcolor.endcolor, tcolor.green, str(parsed_output['FULL_URL'][_]), tcolor.endcolor))
                                if (output_path != ''):
                                    output_to_file(str(parsed_output['FULL_URL'][_]))


                        except:
                            pass
                            #traceback.print_exc()
                            #print("ERROR: "+resp.text)
                        #print("trying new url: "+parsed_output['FULL_URL'][_])
                        #print("Object Body: ")
                        #print(parsed_output['FULL_URL'])
                        #print("Response:\n"+resp.text)
                        #if resp.status_code == 200:
                         #   print("Got 200 for url "+parsed_output['FULL_URL'][_])
                          #  observed_urls.append(parsed_output['FULL_URL'][_])
                    except:
                        pass
                        #traceback.print_exc()
                        #print('%s[!] Error: There was an error in adding a URL into DB.%s' % (tcolor.red, tcolor.endcolor))
                    #print('%s[New URL]: %s %s%s%s' % (tcolor.yellow, tcolor.endcolor, tcolor.green, str(parsed_output['FULL_URL'][_]), tcolor.endcolor))
                    if (output_path != ''):
                        output_to_file(str(parsed_output['FULL_URL'][_]))

            for _ in range(len(parsed_output['CLIENT_IP_ADDRESS'])):
                if (parsed_output['CLIENT_IP_ADDRESS'][_] not in observed_ips):
                    observed_ips.append(parsed_output['CLIENT_IP_ADDRESS'][_])
                    print('%s[New Client]: %s%s' % (tcolor.purple, parsed_output['CLIENT_IP_ADDRESS'][_], tcolor.endcolor))

            # Full Logging, if enabled:
            if (full_logging is True):
                for _ in range(len(parsed_output['FULL_URL'])):
                    Timestamp = calendar.timegm(time.gmtime())
                    try:
                        IP_Address = parsed_output['CLIENT_IP_ADDRESS'][_]
                    except Exception as e:
                        IP_Address = ''
                        Exception_Handler(e)
                    try:
                        VHOST = parsed_output['VHOST'][_]
                    except Exception as e:
                        VHOST = ''
                        Exception_Handler(e)
                    try:
                        REQUEST_URI = parsed_output['REQUEST_URI'][_]
                    except Exception as e:
                        REQUEST_URI = ''
                        Exception_Handler(e)
                    try:
                        FULL_URL = parsed_output['FULL_URL'][_]
                    except Exception as e:
                        FULL_URL = ''
                        Exception_Handler(e)
                    DBHandler().Add_Full_Log(Timestamp, IP_Address, VHOST, REQUEST_URI, FULL_URL)

        time.sleep(int(sleeping_time))
    return(0)


try:
    main(url, full_logging=enable_full_logging)
except KeyboardInterrupt:
    print('\nExiting...')
    exit(0)
except Exception as e:
    Exception_Handler(e)
