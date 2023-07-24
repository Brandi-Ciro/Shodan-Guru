from shodan import Shodan, APIError

import Service as S
import Target as T


class ShodanClient:

    def __init__(self, api: str) -> None:
        self.client = Shodan(api)

    def get_host(self, ip_address: str):
        try:
            print("Obtaining info from a host...")

            # Lookup the host (example: 192.167.9.3)
            results = self.client.host(ip_address)
            print("Host found on Shodan Database...")

            target = T.Target(results["ip_str"], results["asn"],
                              results["country_code"], results["country_name"],
                              results["city"], results["org"],
                              results["last_update"], len(results["ports"]))

            # Inserting just the code of vulnerabilities to print it
            # in low level verbosity.
            if "vulns" in results:
                for vuln_code in results["vulns"]:
                    target.vulns.append(vuln_code)

            # Checking open ports and initializating services.
            if "data" in results:
                # print(len(results['data']))
                for i in range(0, len(results['data'])):
                    # Inizialization service objects
                    tmp_serv = S.Service(results['data'][i])
                    target.open_ports.append(tmp_serv)

            # Order list by port number
            target.open_ports = sorted(target.open_ports, key=lambda service: service.port)
            # Return object
            return target
        except APIError as e:
            print('error: %s' % e)

    def search(self, query_str, num_result):
        target_list = []
        try:
            results = self.client.search(query_str, 1, num_result)
            for result in results['matches']:
                target_list.append(self.get_host(result["ip_str"]))

            # Returns the list of targets because ShodanServer acts like a Factory with its Factory Method Pattern.
            return target_list

        except APIError:
            print("Please upgrade your API plan to use filters or paging")
            exit()

    def search_by_vuln(self, vulns, target_filter, num_result):
        target_list = self.search(target_filter, num_result)
        positive_list = []

        # Aggiunge target alla lista dei target con almeno una delle vulnerabilita'.
        for target in target_list:
            print("Analyzing host with IP: %s" % target.ip_address)
            for vuln in vulns:
                if vuln in target.vulns:
                    positive_list.append(target)

        # Returns the list of targets because ShodanServer acts like a Factory with its Factory Method Pattern.
        return positive_list

    @staticmethod
    def show_filter():
        print("### FILTERS ###")
        print("1 - General Filter")
        print("2 - HTTP Filters")
        print("3 - NTP Filters")
        print("4 - SSL Filters")
        print("5 - Telnet Filters")
        print("6 - Exit")
        print("Choice:")
        c = input()
        switcher = {
            '1': ShodanClient.general_filter,
            '2': ShodanClient.http_filter,
            '3': ShodanClient.ntp_filter,
            '4': ShodanClient.ssl_filter,
            '5': ShodanClient.telnet_filter,
            '6': exit,
        }
        # Get the function from switcher dictionary
        func = switcher.get(c, lambda: "Invalid choice")
        # Execute the function
        func()

    @staticmethod
    def general_filter():
        print("### GENERAL FILTER ###")
        print("# - Name - Description - Type")
        print("##########################################################################")
        print("1 - after - Only show results after the given date (dd/mm/yyyy) - string")
        print("2 - asn - Autonomous system number - string")
        print("3 - before - Only show results before the given date (dd/mm/yyyy) - string")
        print("4 - category - Available categories: ics, malware - string")
        print("5 - city - Name of the city - string")
        print("6 - country - 2-letter country code - string")
        print("7 - geo - Accepts between 2 and 4 parameters. If 2 parameters:" +
              "latitude,longitude. If 3 parameters:" +
              "latitude,longitude,range. If 4 parameters: top left" +
              "latitude, top left longitude, bottom right latitude," +
              "bottom right longitude.- string")
        print("8 - hash - Hash of the data property - string")
        print("9 - has_ipv6 - True/ False - boolean")
        print("10 - has_screenshot - True/ False - boolean")
        print("11 - hostname - Full hostname for the device - string")
        print("12 - ip - Alias for net filter - string")
        print("13 - isp - ISP managing the netblock - string")
        print("14 - net - Network range in CIDR notation (ex. 199.4.1.0/24) - string")
        print("15 - org - Organization assigned the netblock - string")
        print("16 - os - Operating system - string")
        print("17 - port - Port number for the service - string")
        print("18 - postal - Postal code (US-only) - string")
        print("19 - product - Name of the software/ product providing the banner - string")
        print("20 - region - Name of the region/ state - string")
        print("21 - state - Alias for region - string")
        print("22 - version - Version for the product - string")
        print("23 - vuln - CVE ID for a vulnerability - string")
        print("##########################################################################")
        while True:
            print("press b to go back")
            c = input()
            if c == "b":
                ShodanClient.show_filter()

    @staticmethod
    def http_filter():
        print("### HTTP FILTER ###")
        print("# - Name - Description - Type")
        print("##########################################################################")
        print("1 - http.component - Name of web technology used on the website - string")
        print("2 - http.component_category - Category of web components used on the website - string")
        print("3 - http.html - HTML of web banners - string")
        print("4 - http.html_hash - Hash of the website HTML - integer")
        print("5 - http.status - Response status code - integer")
        print("6 - http.title - Title for the web banner’s website - string")
        print("##########################################################################")
        while True:
            print("press b to go back")
            c = input()
            if c == "b":
                ShodanClient.show_filter()

    @staticmethod
    def ntp_filter():
        print("### NTP FILTER ###")
        print("# - Name - Description - Type")
        print("##########################################################################")
        print("1 - ntp.ip - IP addresses returned by monlist - string")
        print("2 - ntp.ip_count - Number of IPs returned by initial monlist - integer")
        print("3 - ntp.more - True/ False; whether there are more IP addresses to be gathered from monlist - boolean")
        print("4 - ntp.port - Port used by IP addresses in monlist - integer")
        print("##########################################################################")
        while True:
            print("press b to go back")
            c = input()
            if c == "b":
                ShodanClient.show_filter()

    @staticmethod
    def ssl_filter():
        print("### SSL FILTER ###")
        print("# - Name - Description - Type")
        print("##########################################################################")
        print("1 - has_ssl - True/ False - boolean")
        print("2 - ssl - Search all SSL data - string")
        print("3 - ssl.alpn - Application layer protocols such as HTTP/2 (“h2”) - string")
        print("4 - ssl.chain_count - Number of certificates in the chain - integer")
        print("5 - ssl.version - Possible values: SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2- string")
        print("6 - ssl.cert.alg - Certificate algorithm - string")
        print("7 - ssl.cert.expired - True/ False - boolean")
        print("8 - ssl.cert.extension - Names of extensions in the certificate - string")
        print("9 - ssl.cert.serial - Serial number as an integer or hexadecimal string - integer/ string")
        print("10 - ssl.cert.pubkey.bits - Number of bits in the public key - integer")
        print("11 - ssl.cert.pubkey.type - Public key type - string")
        print("12 - ssl.cipher.version - SSL version of the preferred cipher - string")
        print("13 - ssl.cipher.bits - Number of bits in the preferred cipher - integer")
        print("14 - ssl.cipher.name - Name of the preferred cipher - string")
        print("##########################################################################")
        while True:
            print("press b to go back")
            c = input()
            if c == "b":
                ShodanClient.show_filter()

    @staticmethod
    def telnet_filter():
        print("### Telnet FILTER ###")
        print("# - Name - Description - Type")
        print("##########################################################################")
        print("1 - telnet.option - Search all the options - string")
        print("2 - telnet.do - The server requests the client do support these options - string")
        print("3 - telnet.dont - The server requests the client to not support these options - string")
        print("4 - telnet.will - The server supports these options - string")
        print("5 - telnet.wont - The server doesn’t support these options - string")
        print("##########################################################################")
        while True:
            print("press b to go back")
            c = input()
            if c == "b":
                ShodanClient.show_filter()
