class Target:

    #Le porte sono a loro volta oggetti e la classe target
    #contiene una lista di porte aperte con i dati sulle vulnerabilità.
    #open_ports = []

    def __init__(self):
        self.ip_address = 'unknown'
        self.asn = 'unknown'
        self.country_code = 'unknown'
        self.country_name = 'unknown'
        self.city = 'unknown'
        self.org = 'unknown'
        self.last_update = 'unknown'
        self.no_of_open_ports = 0
        self.open_ports = []

        # List of strings representing only the codenames of the vulnerabilities
        # used to print just minimum info about the target. (low level verbosity)
        self.vulns = []



    def __init__(self, ip_address, asn, country_code, country_name, city, org, last_update,no_of_open_ports):
        self.ip_address = ip_address
        self.asn = asn
        self.country_code = country_code
        self.country_name = country_name
        self.city = city
        self.org = org
        self.last_update = last_update
        self.no_of_open_ports = no_of_open_ports
        self.open_ports = []

        # List of strings representing only the codenames of the vulnerabilities
        # used to print just minimum info about the target. (low level verbosity)
        self.vulns = []


    '''verbosity can be set to low or high. 
       Low level shows only basic info.
       High level shows all the gathered info.'''

    def print(self, verbosity=0):
            print("Host data from Shodan Database is the following...")
            print("IP Address: % s " % self.ip_address)
            print("Autonomous System: % s " % self.asn)
            print("Country code: % s " % self.country_code)
            print("Country name: % s " % self.country_name)
            print("City: % s " % self.city)
            print("Organization: % s " % self.org)
            print("Last update: % s " % self.last_update)
            if self.no_of_open_ports != 0:
                print("Number of open ports: % s" % self.no_of_open_ports)

            if self.vulns:
                print("Vulnerabilities: ")
                for vuln_code in self.vulns:
                    print("%s\t" % vuln_code, end = '')
                print("\n")

            if self.open_ports:
                print("Ports: ")
                #print(self.open_ports)
                for service in self.open_ports:
                    service.print(verbosity)