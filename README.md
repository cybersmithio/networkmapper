# networkmapper

This script pulls data out of a Tenable product and generates a network map using Plotly. It works with either Tenable.io or Tenable.sc.

This is using pyTenable, so be sure you have that installed: https://pytenable.readthedocs.io/en/stable/index.html

# Capabilitites

So what can the networkmapper do for you?  Here are the current capabilities:
* Identify and draw subnets from data in your Tenable products.
* Identify and draw gateways from data in your Tenable products.
* Identify and draw hosts from data in your Tenable products.
* Identify and draw Nessus sensors within your environment.
* Anonymize the maps drawn by removing IP address information.
* Color code the subnets and hosts to show the highest level of vulnerability severity in your environment.
* Color code the subnets and hosts to show the spectrum of vulnerabilities in your environment.
* Exclude drawing subnets that do not have any hosts.
* Exclude drawing subnets or hosts with public IP addresses.
* Dump the relevant data gathered from your Tenable products to a file.
* Create a map from a previous data dump.
* Only use data of a certain age or less to generate the map.

# Quick start
This will generate a standard network map using best practices.

```
TIO_ACCESS_KEY="**************"; export TIO_ACCESS_KEY
TIO_SECRET_KEY="**************"; export TIO_SECRET_KEY
python3 networkmapper.py --exclude-public --ignore-empty-subnets
```


# Tenable.io map using API key environment variables

This example shows how to pull data from Tenable.io.  In this example, the API keys are provided using environment variables, which is best practice.

```
TIO_ACCESS_KEY="**************"; export TIO_ACCESS_KEY
TIO_SECRET_KEY="**************"; export TIO_SECRET_KEY
python3 networkmapper.py
```


# Tenable.io map using CLI API key

This example shows how to pull data from Tenable.io using API keys specified on the command line interface.
Since this would save the API keys in the shell history, this is not recommended for security reasons.

```
python3 networkmapper.py --accesskey ********* --secretkey *********
```

# Tenable.sc map using credentials in environment variables

This example shows how to pull data from Tenable.io.  In this example, the API keys are provided using environment variables, which is best practice.

```
SC_USERNAME="**************"; export SC_USERNAME
SC_PASSWORD="**************"; export SC_PASSWORD
python3 networkmapper.py --host 127.0.0.1 --port 8443
```


# Tenable.sc map with CLI credentials
This example shows how to pull data from Tenable.sc using credentials specified on the command line interface.
Since this would save the credentials in the shell history, this is not recommended for security reasons.

```
python3 networkmapper.py --username ********* --password ******** --host 127.0.0.1 --port 8443
```


# Save results to a file

To save the data gathered by the network mapper, use the outputfile parameter.  This will dump a JSON file that can be used in subsequent runs of the network mapper.

```
python3 networkmapper.py --outputfile output.json
```

# Load previous saved results to a file

This example generates the diagrams from a previously saved JSON file. (See previous example)

```
python3 networkmapper.py --offlinefile output.json
```

# Excluding public IP information
The network mapper will generate maps from all the data gathered by Tenable products.  In many cases the public IP information is not required for a network map.
The exclude-public parameter will prevent public IP addresses from being included in the maps.

```
python3 networkmapper.py --exclude-public
```



# Example of running in debug mode.

*very* verbose and really only for the developer's debugging purposes

```
python3 networkmapper.py --debug
```


# Getting better maps

Maps are going to show proper topology when these rules are following:
 * Do host discovery scans on all subnets.
 * For each subnet, scan from a Nessus scanner installed locally on that subnet.  This will allow hosts that do not respond to at least be discovered by ARP pings.
 * For each subnet, scan from a Nessus scanner on another nearby subnet. This will allow the mapper to determine which subnets are connected to the same router/firewall.
   * Only do this if your firewall will not respond to ever single request.  Ideally, just have a rule saying the Nessus scanner can ping live hosts on other subnets.
 * Do credentialed or agent scans on all systems.  This allows subnet netmask information to be discovered, which helps in drawing.
 * Scan frequently to you have up-to-date information, and then restrict the network mapper to only use plugin data of a certain age.  This keeps the maps fresh.
 * Avoid overlapping IP addresses in your network.  At this point, this is just going to mess things up in the diagram.

Plugins used by the network mapper include:
 * 24272
 * 10663
 * 10287
 * 12


