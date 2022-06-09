#!/usr/bin/env python
import BaseHTTPServer, cgi, cStringIO, glob, httplib, json, os, pickle, random, re, SocketServer, sqlite3, string, sys, subprocess, time, traceback, urllib, xml.etree.ElementTree
try:
    import lxml.etree
except ImportError:
    print "[!] Successful execution connected to http://localhost:8000 \n If you want to run it install 'python-lxml' (e.g. '%s')\n " % ("apt install python-lxml" if not subprocess.mswindows else "https://pypi.python.org/pypi/lxml")

NAME, VERSION, GITHUB, AUTHOR, LICENSE = "Sec Lab Exam 25 June (2021) < Path Traversal Challenge", "0.01", "https://gitlab.com/wild_boar/labsec_course", "@wild_boar", "GPLv3"
LISTEN_ADDRESS, LISTEN_PORT = "0.0.0.0", 8000
HTML_PREFIX, HTML_POSTFIX = "<!DOCTYPE html>\n<html>\n<head>\n<style>a {font-weight: bold; text-decoration: none; visited: blue; color: blue;} ul {display: inline-block;} .disabled {text-decoration: line-through; color: gray} .disabled a {visited: gray; color: gray; pointer-events: none; cursor: default} table {border-collapse: collapse; margin: 12px; border: 2px solid black} th, td {border: 1px solid black; padding: 3px} span {font-size: larger; font-weight: bold}</style>\n<title>%s</title>\n</head>\n<body style='font: 12px monospace'>\n<script>function process(data) {alert(\"Surname(s) from JSON results: \" + Object.keys(data).map(function(k) {return data[k]}));}; var index=document.location.hash.indexOf('lang='); if (index != -1) document.write('<div style=\"position: absolute; top: 5px; right: 5px;\">Chosen language: <b>' + decodeURIComponent(document.location.hash.substring(index + 5)) + '</b></div>');</script>\n" % cgi.escape(NAME), "<div style=\"position: fixed; bottom: 5px; text-align: center; width: 100%%;\">Powered by <a href=\"%s\" style=\"font-weight: bold; text-decoration: none; visited: blue; color: blue\" target=\"_blank\">%s</a> (v<b>%s</b>)</div>\n</body>\n</html>" % (GITHUB, "@wild_boar", VERSION)
USERS_XML = """<?xml version="1.0" encoding="utf-8"?><users><user id="0"><username>admin</username><name>admin</name><surname>admin</surname><password>7en8aiDoh!</password></user></users>"""

def init():
    global connection
    connection = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, name TEXT, surname TEXT, password TEXT)")
    cursor.executemany("INSERT INTO users(id, username, name, surname, password) VALUES(NULL, ?, ?, ?, ?)", ((_.findtext("username"), _.findtext("name"), _.findtext("surname"), _.findtext("password")) for _ in xml.etree.ElementTree.fromstring(USERS_XML).findall("user")))
    cursor.execute("CREATE TABLE comments(id INTEGER PRIMARY KEY AUTOINCREMENT, comment TEXT, time TEXT)")

class ReqHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        path, query = self.path.split('?', 1) if '?' in self.path else (self.path, "")
        code, content, params, cursor = httplib.OK, HTML_PREFIX, dict((match.group("parameter"), urllib.unquote(','.join(re.findall(r"(?:\A|[?&])%s=([^&]+)" % match.group("parameter"), query)))) for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)([^&]+)", query)), connection.cursor()
        try:
            if path == '/':
                if "path" in params:
                    paths=str(params["path"])
                    if re.search("^\.\./",paths):
                        content = "Error! Can't invoke a path starting with ../, are you sure it's a path traversal?"
                    elif re.search("^/\.\.",paths):
                        content = "Error! It is not possible to invoke a path starting with /.., are you sure it is a traversal path?"
                    elif re.search("^//",paths):
			content = "Error! It's also not possible to invoke a path with //, maybe you can make something newest and combination of both?"
		    elif re.search("^/[a-zA-Z0-9]+",paths):
                        content = "Error! We have disabled the ability to directly invoke the /etc/passwd file, the path parameter cannot start with / followed by any alphanumeric character. HINT: / + alphanumeric character, what is left out?"
                    elif re.search("wd$",paths):
                        content = "Error! The path cannot end with \"wd\", what can you use to overide this +wild+ filter?"
                    else:
                        print glob.glob(paths)
                        final = glob.glob(paths)[0]
                        print final
                        content = (open(os.path.abspath(final), "rb") if not "://" in final else urllib.urlopen(final)).read()
                elif "redir" in params:
                    content = content.replace("<head>", "<head><meta http-equiv=\"refresh\" content=\"0; url=%s\"/>" % params["redir"])
                if HTML_PREFIX in content and HTML_POSTFIX not in content:
                    content +="<div><span>Web Challenge EXam 25 June 2021:</span></div>\n"
                    content +="<p> The challenge is to exploit a LFI (Local File Inclusion) </p>"
                    content +="<p> Through a GET request to the root / with the path parameter it is possible to open a local file e.g. /?path=file_locale.txt</p>"
                    content +="<p> The purpose of this exercise is to exploit the LFI and retrieve/read the file /etc/passwd</p>"
                    content +="<p> There are some filters on the characters that you can send as a path</p>"
                    content +="<p> For each filter \"matched\" a small hint will be proposed</p>"
                    content +="<p> The student must the submit 3 files</p>"
                    content +="<p> 1) The file report.txt where he/she should explain in a understandable way the concept behind the vulnerability of this challenge</p>"
                    content +="<p> The student should also list the various steps and attempts made to exploit the vulnerability, with the reasoning behind bypasssing the filters, including of course the final payload</p>"
                    content +="<p> 2) The screenshot where you can clearly see the call to the application with the payload and the final result  </p>"
                    content +="<p> 3) The etc/passwd file </p>"
                    content +="<p> The quality of the report will affect the evaluation of the practical part.</p>"
            else:
                code = httplib.NOT_FOUND
        except Exception, ex:
            content = ex.output if isinstance(ex, subprocess.CalledProcessError) else traceback.format_exc()
            code = httplib.INTERNAL_SERVER_ERROR
        finally:
            self.send_response(code)
            self.send_header("Connection", "close")
            self.send_header("X-XSS-Protection", "0")
            self.send_header("Content-Type", "%s%s" % ("text/html" if content.startswith("<!DOCTYPE html>") else "text/plain", "; charset=%s" % params.get("charset", "utf8")))
            self.end_headers()
            self.wfile.write("%s%s" % (content, HTML_POSTFIX if HTML_PREFIX in content and GITHUB not in content else ""))
            self.wfile.flush()
            self.wfile.close()

class ThreadingServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    pass

if __name__ == "__main__":
    init()
    print "%s #v%s\n by: %s\n\n[i] The execution was succesfull you can connect via browser to'%s:%d'..." % (NAME, VERSION, AUTHOR, LISTEN_ADDRESS, LISTEN_PORT)
    try:
        ThreadingServer((LISTEN_ADDRESS, LISTEN_PORT), ReqHandler).serve_forever()
    except KeyboardInterrupt:
        os._exit(1)
