#!/usr/bin/env python
import BaseHTTPServer, cgi, cStringIO, httplib, json, os, pickle, random, re, SocketServer, sqlite3, string, sys, subprocess, time, traceback, urllib, xml.etree.ElementTree
try:
    import lxml.etree
except ImportError:
    print "[!] Se si vuole runnarlo in locale installare 'python-lxml' (e.g. '%s')\n" % ("apt install python-lxml" if not subprocess.mswindows else "https://pypi.python.org/pypi/lxml")

NAME, VERSION, GITHUB, AUTHOR, LICENSE = "Sec Lab Esame 11 Giugno (2021) < SQLi challenge (Login Bypass)", "0.01", "https://gitlab.com/wild_boar/labsec_course", "@wild_boar", "GPLv3"
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
                if HTML_PREFIX in content and HTML_POSTFIX not in content:
                    content += "<div><span>Web Challenge Esame 11 Giugno 2021:</span></div>\n<p> La challenge consiste nello sfruttare una sql injection per bypassare il login</p><p> Il login si effettua attraverso una chiamata GET al indirizzo /login con parametri username e password e.g. /login?username=&password=</p><p> Scopo dell'esercitazione e\' loggarsi come utente admin</p><p> Per risultare corretto l\'esercizio lo studente deve consegnare un file web.txt contenente: la FLAG, la query completa che sfrutta l\'SQLi, una breve descrizione sui passaggi eseguiti, il perche\' la vulnerabilita\' esiste e come viene sfruttata.  </p><p> Consegnare soltanto la Flag non sara\' ritenuto sufficente. Il livello di dettaglio e precisione della descrizione sara\' utilizzato come valutazione della prova.</p>"
            elif path == "/login":
                paths=str(params["password"])
                if re.search("OR",paths):
                    content = "OR disabilitato"
                elif re.search("or",paths):
                    content = "or disabilitato"
                elif re.search("Or",paths):
                    content = "Or disabilitato"
                elif re.search("=",paths):
                    content = "= disabilitato"
                else:
                        # print glob.glob(paths)
                        # final = glob.glob(paths)[0]
                        # print final                
                    cursor.execute("SELECT * FROM users WHERE username='" + re.sub(r"[^\w]", "", params.get("username", "")) + "' AND password='" + params.get("password", "") + "'")
                    content += "Welcome Student Here is your flag: SEC{Today_a_young_man_on_acid_realized_that_all_matter_is_merely_energy_condensed_to_a_slow_vibration_that_we_are_all_one_consciousness_experiencing_itself_subjectively,_there_is_no_such_thing_as_death,_life_is_only_a_dream,_and_we_are_the_imagination_of_ourselves._Here\'s_Tom_with_the_weather.}<b>%s</b><meta http-equiv=\"Set-Cookie\" content=\"SESSIONID=%s; path=/\"><meta http-equiv=\"refresh\" content=\"1; url=/\"/>" % (re.sub(r"[^\w]", "", params.get("username", "")), "".join(random.sample(string.letters + string.digits, 20))) if cursor.fetchall() else "The username and/or password is incorrect<meta http-equiv=\"Set-Cookie\" content=\"SESSIONID=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT\">"
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
    print "%s #v%s\n by: %s\n\n[i] running HTTP server at '%s:%d'..." % (NAME, VERSION, AUTHOR, LISTEN_ADDRESS, LISTEN_PORT)
    try:
        ThreadingServer((LISTEN_ADDRESS, LISTEN_PORT), ReqHandler).serve_forever()
    except KeyboardInterrupt:
        os._exit(1)
