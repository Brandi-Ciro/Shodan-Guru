import sys
import ShodanServer as S
import Target as T

# Per l'ultima versione dei banner consultare: https://developer.shodan.io/api/banner-specification

# Put your Shodan API here before executing ShodanGuru!
user_api = ''

if user_api == '':
    print("Please insert your API into ShodanGuru.py before starting querying Shodan Database. ")
else:
    s_server = S.ShodanServer(user_api)

    if len(sys.argv) != 1:
        if sys.argv[1] == "-h" or sys.argv[1] == "help":
            S.ShodanServer.show_filter()
        if sys.argv[1] == "host":
            # Check if the Verbosity is been specified
            if len(sys.argv) >= 4:
                if len(sys.argv) == 4:
                    if sys.argv[3] == '0' or sys.argv[3] == '1':
                        target = s_server.get_host(sys.argv[2])
                        target.print(int(sys.argv[3]))
                    else:
                        print("Error! Verbosity level specified must be 0 (low) or 1 (high).")
                else:
                    print("Error! Too many arguments found! Check the manual typing -h.")
            # Default level of Verbosity is 0(low)
            else:
                target = s_server.get_host(sys.argv[2])
                target.print(0)


        if sys.argv[1] == "search":
            # Il numero di risultati non deve essere più di 20
            if int(sys.argv[3]) <= 20:
                target_list = s_server.search(sys.argv[2], sys.argv[3])
                print("List of hosts matching with the requested filter:")
                if len(sys.argv) == 5 and sys.argv[len(sys.argv) - 1] == 1:
                    for t in target_list:
                        print("\n")
                        t.print(1)
                else:
                    for t in target_list:
                        print("\n")
                        t.print(0)
            else:
                print("Error! Too much results specified. Max permitted is 20. Modify the code to remove the limit.")
        if sys.argv[1] == 'vuln':
            vulnerabilities_list = []
            n_arg = len(sys.argv)

            for i in range(2, len(sys.argv)-2):
                vulnerabilities_list.append(sys.argv[i])

            tvl_list = s_server.search_by_vuln(vulnerabilities_list, sys.argv[n_arg - 2], sys.argv[n_arg - 1])
            if len(tvl_list) == 0:
                print("\n No host found with specified vulnerabilities.")
            for t in tvl_list:
                print("\n")
                t.print(0)