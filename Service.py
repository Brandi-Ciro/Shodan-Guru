# Authors: Marco Urbano & Ciro Brandi

import Vulnerability as V
# La classe service rappresenta un singolo servizio (es. HTTP, HTTPS) e
# contiene tutte le informazioni sia sulla porta di comunicazione che
# sulle vulnerabilità.

class Service:


    def __init__(self):
        self.module = ''
        self.info = ''
        self.transport = ''
        self.devicetype = ''
        self.os = ''
        self.isp = ''
        self.data = ''
        self.port = ''
        self.version = ''
        self.timestamp = ''
        self.uptime = ''
        self.hostname = ''
        self.ssl_versions = []
        self.vulnerabilities = []

    def __init__(self, json_object):

        self.module = ''
        self.info = ''
        self.transport = ''
        self.devicetype = ''
        self.os = ''
        self.isp = ''
        self.data = ''
        self.port = ''
        self.version = ''
        self.timestamp = ''
        self.uptime = ''
        self.product = ''
        self.ssl_versions = []
        self.vulnerabilities = []
        # Campo opzionale che rappresenta l'hostname generico
        self.options_hostname = ''
        # Lista di stringhe di hostname relativi ad un servizio.
        self.hostnames = []

        if "_shodan" in json_object:
            if "module" in json_object["_shodan"]:
                self.module = json_object["_shodan"]["module"]
            if "options" in json_object["_shodan"]:
                if "hostname" in json_object["_shodan"]["options"]:
                    self.options_hostname = json_object["_shodan"]["options"]["hostname"]

        if "hostnames" in json_object:
            self.hostnames = json_object["hostnames"]

        if "info" in json_object:
            self.info = json_object["info"]

        if "transport" in json_object:
            self.transport = json_object["transport"]

        if "devicetype" in json_object:
            self.devicetype = json_object["devicetype"]

        if "os" in json_object:
            self.os = json_object["os"]

        if "isp" in json_object:
            self.isp = json_object["isp"]

        if "data" in json_object:
            self.banner = json_object["data"]

        if "port" in json_object:
            self.port = json_object["port"]

        if "version" in json_object:
            self.version = json_object["version"]

        if "timestamp" in json_object:
            self.timestamp = json_object["timestamp"]

        if "uptime" in json_object:
            self.uptime = json_object["uptime"]

        if "product" in json_object:
            self.product = json_object["product"]

        if "ssl" in json_object:
            if "versions" in json_object["ssl"]:
                for ssl_vers in json_object["ssl"]["versions"]:
                    #print(ssl_vers)
                    self.ssl_versions.append(ssl_vers)

        if "vulns" in json_object:
            # Inizialization of vulnerability objects
            current_vulns = json_object['vulns']
            # Collecting dictionary keys and using them to obtain vulnerabilities
            code_vuln = current_vulns.keys()
            for code in code_vuln:
                # Richiama costruttore per ogni vulnerabilità
                vuln = V.Vulnerability(code, current_vulns[code]["cvss"],
                                       current_vulns[code]["summary"],
                                       current_vulns[code]["verified"])

                # Ogni riferimento è una stringa, ogni vulnerabilità
                # contiene una lista di stringhe che indicano i riferimenti.
                for ref in current_vulns[code]["references"]:
                    vuln.references.append(ref)

                self.vulnerabilities.append(vuln)

    def print(self, verbosity):
        if verbosity == 0:
            print("%s/%s %s %s" % (self.port, self.transport, self.product, self.version))
            if self.ssl_versions:
                print("   |-- SSL VERSIONS: %s" % self.ssl_versions)
        else:
            print("\n")
            print("Module: % s\t" % self.module)
            print("Transport protocol: % s" % self.transport)
            print("Device type: % s" % self.devicetype)
            print("OS: % s" % self.os)
            print("ISP: %s" % self.isp)
            print("Port: %s" % self.port)
            print("Hostname: %s" % self.options_hostname)
            print("Hostnames: %s" % self.hostnames)
            print("Version: %s" % self.version)
            print("Timestamp: %s" % self.timestamp)
            print("Uptime: %s" % self.uptime)
            print("Info: %s" % self.info)
            print("Banner: %s \n" % self.banner)

            # Stampa le vulnerabilità del servizio.
            for vuln in self.vulnerabilities:
                vuln.print(verbosity)
