#python3.5

''' msgb -- encode and decode messages '''

import argparse
import getpass
import hashlib
import os
import sqlite3
import sys

import rciph
import settings

PATH = settings.sroot

_db = ["msgb", "appd", "msgb", "msgb.db"] # add dir path to file location to this list (ie. ["C:", ..., "msgb", ...])
_shad = ["msgb", "appd", "_shadow", "msgb.shd"] # add dir path to file location to this list (ie. ["C:", ..., "msgb", ...])

DB = "/".join(_db) #local filepath
SHADOW = "/".join(_shad) #local shadow file

SUPPORTED_COMMANDS = ('addMsg', 'addUser', 'chPass', 'help', 'new-rsa', 'readMsg')

## SECTION I -- backend
def runas_admin():
	runas_admin = input("Is msgb running as Administrator? [y/n] ")
	if runas_admin.lower().startswith('y'):
		return True
	else:
		print("Rerun this program as Admin in order to register new users.")
		sys.exit(0)

def newRSA():
	# uses os.popen because importing rsa_key_generator.py doesn't work (can't import rabin_miller)
	KEYSIZE = 1024
	warning_msg = '''ATTENTION! Replacing your RSA keys will make data stored with the current keys \
	unrecoverable. (The current version of msgb doesn't have a conversion function).\nContinue? [y/n] '''
	c = input(warning_msg)
	if c.lower().startswith('y'):
		pass
	else:
		sys.exit(0)
	usern = input("Username: ")
	passw = getpass.getpass()

	_pword = readShadow(usern)

	if hashlib.sha512(passw.encode("utf-8")).hexdigest() == _pword:
		with os.popen("python %(dp)s/rsa/rsa_key_generator.py %(n)s" % {"dp": PATH, "n": usern}, 'r') as f:
			print(f.read())
	else:
		print("Password incorrect.")
		sys.exit(1)

def helpf():
	cmd = """Supported subcommands:
	addMsg -- register a new entry in database; requires KEY and MSG
	addUser -- register a new username for the tool
	chPass -- change password; run as Admin; manually edit security to ensure data safety
	help -- print this message
	new-rsa -- create new RSA PUB and PRIV keys; will create files in the directory msgb was called from
	readMsg -- read the saved message from the database; requires the appropriate KEY"""
	print(cmd)

## SECTION II -- reading from SHADOW; only requires addUser
def readShadow(user):
	with open(SHADOW, 'r') as f:
		for line in f.read().split("\n"):
			if line.startswith(user):
				return line.split("::")[1]
			else:
				pass
	return None # if user not registered

def get_usepass():
	usern = input("Username: ")
	phash = readShadow(usern)
	if phash is not None:
		pword = getpass.getpass()
		if phash == hashlib.sha512(pword.encode("utf-8")).hexdigest():
			return usern
		else:
			print("Password given does not match password stored.")
			sys.exit(1)
	else:
		print("That username is not registered. Use `addUser` to register a new user.")
		sys.exit(1)

## SECTION II.A -- addUser; only requires addUser
def yName():
	with open(SHADOW, 'r') as f:
		for line in f.read().split("\n"):
			yield line.split("::")[0]

def addUser():
	usern = input("Username: ")
	for n in yName():
		if usern == n:
			print("Username %(u)s already registered! Select a different one.")
			addUser()
		else:
			pass

	_pword = getpass.getpass()
	print("\nRetype password")
	_second = getpass.getpass()

	if _pword == _second:
		pass
	else:
		print("Passwords didn't match, program exitting.")
		sys.exit(2)

	pword = hashlib.sha512(_pword.encode("utf-8")).hexdigest()
	with open(SHADOW, 'a') as f:
		f.write("%(u)s::%(p)s\n" % {"u": usern, "p": pword})

	print("Username successfully added.")

## SECTION II.B -- chPass; only requires chPass
def chPass(user):
	oldpass = readShadow(user)
	print("Enter your current password")
	checkpass = getpass.getpass()
	print("\nEnter new password")
	np1 = getpass.getpass()
	print("Retype password")
	np2 = getpass.getpass()

	if np1 == np2:
		np = hashlib.sha512(np1.encode("utf-8")).hexdigest()
	else:
		print("Passwords didn't match, program exitting.")
		sys.exit(2)

	with open(SHADOW, 'r') as f:
		newdata = []
		for line in f.read().split("\n"):
			if line.startswith(user):
				newdata.append("%(u)s::%(p)s" % {"u": user, "p": np})
			else:
				newdata.append(line)

	with open(SHADOW, 'w') as f:
		f.write("\n".join(newdata))


## SECTION III -- db interface; requires key and msg

def dbStart():
	if os.path.exists(DB):
		return True
	else:
		conn = sqlite3.connect(DB)
		conn.close()
		return False

def mktable(user):
	SQLCMD = '''CREATE TABLE "msg_box_%(u)s" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, \
	"user" varchar(140) NOT NULL, \
	"key" varchar(140) NOT NULL UNIQUE, \
	"msg" varchar(5000) NOT NULL)''' % {"u": user}
	conn = sqlite3.connect(DB)
	conn.execute(SQLCMD)

def check_table(user):
	if not dbStart():
		mktable(user)
	else:
		SQLCMD = "SELECT name FROM sqlite_master WHERE type='table' AND name='msg_box_%(u)s'" % {"u": user}
		conn = sqlite3.connect(DB)
		cur = conn.cursor()

		r = cur.execute(SQLCMD).fetchall()
		if r:
			pass
		else:
			mktable(user)
		conn.close()

def saveToDatabase(user, key, msg):
	check_table(user) # first, determine if db even exists

	SQLCMD = "INSERT INTO 'msg_box_%(u)s' (user, key, msg) VALUES (?,?,?)" % {"u": user}
	VALUES = (user, key, rciph.enc(msg))
	conn = sqlite3.connect(DB)
	cur = conn.cursor()
	try:
		cur.execute(SQLCMD, VALUES)
		conn.commit()
		print("Entry %(e)d [KEY: %(k)s] added." % {"e": cur.lastrowid, "k": key})
	except sqlite3.IntegrityError as exc:
		print(str(exc))
		print("Entry with [KEY: %(k)s] already exists!" % {'k': key})
	finally:
		conn.close()

def readWithKey(user, key):
	SQLCMD = "SELECT msg FROM msg_box_%(u)s WHERE key='%(k)s' AND user='%(u)s'" % {"u": user, "k": key}
	conn = sqlite3.connect(DB)
	cur = conn.cursor()

	try:
		r = cur.execute(SQLCMD).fetchall()
	except sqlite3.OperationalError as exc:
		print(str(exc))
		sys.exit(6)

	if r:
		print(rciph.dec(r[0][0]))
	else:
		print("No value for KEY: %(k)s" % {"k": key})

## SECTION IV -- setup argparse
parser = argparse.ArgumentParser(prog = "msgb")
parser.add_argument("subcommand", action = "store", nargs = "?", help = "msgb subcommand")
parser.add_argument("key", action = "store", nargs = "?", help = "msg key")
parser.add_argument("msg", action = "store", nargs = "?", help = "msg to store")

if __name__ == "__main__":
	args = parser.parse_args()
	if args.subcommand in SUPPORTED_COMMANDS:
		if args.subcommand == 'addMsg':
			if args.key and args.msg:
				user = get_usepass()
				saveToDatabase(user, args.key, args.msg)
			else:
				print("addMsg requires [KEY, MSG] pair\n>>msgb addMsg [KEY] [MSG]\n\nProgram exitting.")
				sys.exit(4)
		elif args.subcommand == 'addUser':
			if runas_admin():
				addUser()
		elif args.subcommand == 'chPass':
			if runas_admin():
				user = get_usepass()
				chPass(user)
		elif args.subcommand == 'help':
			helpf()
		elif args.subcommand == 'new-rsa':
			newRSA()
		elif args.subcommand == 'readMsg':
			if args.key:
				user = get_usepass()
				readWithKey(user, args.key)
			else:
				print("readMsg requires [KEY]\n>>msgb readMsg [KEY]\n\nProgram exitting.")
				sys.exit(5)
	else:
		print("Unknown subcommand [%(sc)s]. Program exitting." % {'sc': args.subcommand})
		sys.exit(3)