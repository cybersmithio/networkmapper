#!/usr/bin/python
#
# This requires python 3.3 due to the use of the ipaddress library
#
# Takes data from Tenable.io or Tenable.sc and makes a network map.
# Written by: James Smith
#
# Version 5:
#   * Improved subnet plot to show a summary count of the netmasks
#   * Host count in subnet label
#   * Use data of only a certain age
#
# Version 4:
#   * Added count of subnets by netmask on the "Subnet Overview" page
#   * updated visuals
#
# Version 3:
#   * Revamped the variable structure, since it was getting to be a dog's breakfast.
#   * Added CLI flag to exclude public hosts and subnets from map.
#   * Create a download file of all the relevant Tenable data, for debugging purposes
#
# Version 2 - Has functionality to identify when gateways/subnets sharerouters. Jan 3, 2018
# Version 1 - Initial version to gather information and make a basic plot.  Dec 31, 2018
#
# Future capabilities:
#     Creates a file with all the information downloaded from Tenable.io.
#     This file can be used as a source of data in an offline mode, and can be
#     useful for debugging.
#
#   Show router interconnections (if they exist)
#   A mode that outputs a visio macro file for drawing the diagram in visio
#   A list on the subnet page we had 3 lists/tables:
#       - Non RFC-1918 addresses scanned (public IPs, or subnets of public IPs)
#       - Class B subnets (internal)
#       - Class C subnets  (internal)
#  Summary data on each plot, such as the number of subnets, number of gateways, number of scanners, etc
#  Query for all Nessus sensors, including scanners, network monitors, and agent managers, and plot
#
# Example usage with environment variables:
# TIO_ACCESS_KEY=""; export TIO_ACCESS_KEY
# TIO_SECRET_KEY=""; export TIO_SECRET_KEY
# python3 networkmapper.py
#
# This script requires these libraries to be installed:
#     pyTenable
#     plotly
#     networkx
# If this is not already done, then run pip install pytenable plotly networkx
#
# Assumptions and notes:
#  * When drawing the map, if there are subnets that are just one hop away then the assumption is
#    those subnets are connected to the same gateway.
#  * For best results, always have a scanner in each subnet, and have at least a host discovery scan
#    that scans from a Nessus scanner on one subnet to another subnet.  This will build the router map.
#

import json
import os
import sys
from tenable.io import TenableIO
from tenable.sc import TenableSC
import argparse
import re
import ipaddress
from datetime import timedelta
from datetime import datetime


#Testing
#pip install plotly networkx
import plotly.plotly as py
import plotly
import plotly.graph_objs as go
import networkx as nx


def DownloadAssetInfoIO(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age):
    TIO=False
    if str(type(conn))  == "<class 'tenable.io.TenableIO'>":
        TIO=True

    if age != None:
        maximumage=datetime.today()-timedelta(days=int(age))
    else:
        maximumage=datetime(1970,1,1,0,0,0)


    if TIO:
        #Go through each asset downloaded from Tenable.io, parse the data and store it.
        for asset in conn.assets.list():
            IPV4=False
            IPv6=False
            #We need to build a list of addresses so we can filter out things like link-local addresses
            ipaddresses=[]
            if DEBUG:
                print("Asset ID:",asset['id'])
                print("Asset IPv4 addresses:", asset['ipv4']) if 'ipv4' in asset else print("")
                print("Asset info:",asset)
            if datetime.strptime(asset['last_seen'],"%Y-%m-%dT%H:%M:%S.%fZ") >= maximumage:
                if DEBUG:
                    print("This asset has been seen since",maximumage,"so adding it")
                if 'ipv4' in asset:
                    if DEBUG:
                        if len(asset['ipv4']) > 1:
                            print("This is a multi-homed asset")
                    IPV4=True
                    for i in asset['ipv4']:
                        ip=ipaddress.IPv4Address(i)
                        if not ip.is_link_local and not ip.is_loopback and not ip.is_reserved and not ip.is_multicast and not ip.is_unspecified:
                            if EXCLUDEPUBLIC == False or ( EXCLUDEPUBLIC ==True and ip.is_private):
                                tenabledata['ipaddresses'].append(ip)
                                ipaddresses.append(ip)
                if 'ipv6' in asset:
                    if DEBUG:
                        if len(asset['ipv6']) > 1:
                            print("This is a multi-homed asset")
                    IPV6=True
                    for i in asset['ipv6']:
                        ip=ipaddress.IPv6Address(i)
                        if not ip.is_link_local and not ip.is_loopback and not ip.is_reserved and not ip.is_multicast and not ip.is_unspecified:
                            if EXCLUDEPUBLIC == False or ( EXCLUDEPUBLIC ==True and ip.is_private):
                                tenabledata['ipaddresses'].append(ipaddress.IPv6Address(i))
                                ipaddresses.append(ip)
                tenabledata['assets'].append(tuple([len(tenabledata['assets']),asset['id'],ipaddresses]))
            else:
                if DEBUG:
                    print("This asset has not been seen since",maximumage,"so not adding it")
    else:
        try:
            if age == None:
                assets = conn.analysis.vulns(tool="sumip")
            else:
                if int(age) < 1000:
                    assets = conn.analysis.vulns(('lastSeen','=','00:'+str(int(age))),tool="sumip")
                else:
                    assets = conn.analysis.vulns(tool="sumip")
        except:
            assets = []
            print("Error getting ip list", sys.exc_info()[0], sys.exc_info()[1])

        assetcount=0
        for asset in assets:
            assetcount+=1
            if DEBUG:
                print("Asset info:", asset)
            if 'ip' in asset:
                tenabledata['ipaddresses'].append(ipaddress.IPv4Address(asset['ip']))
                tenabledata['assets'].append(tuple([len(tenabledata['assets']),None,asset['ip']]))
        if DEBUG:
            print("Total assets retrieved from tenable.sc:",assetcount)


    if DEBUG:
        print("\n\n\n")
        print("Assets found:",tenabledata['assets'])
        print("IP addresses found:",tenabledata['ipaddresses'])
        print("\n\n\n")

    return(tenabledata)


def DownloadScanners(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age):
    TIO=False
    if str(type(conn))  == "<class 'tenable.io.TenableIO'>":
        TIO=True

    if age != None:
        maximumage=datetime.today()-timedelta(days=int(age))
    else:
        maximumage=datetime(1970,1,1,0,0,0)

    if TIO:
        #Go through each asset downloaded from Tenable.io, parse the data and store it.

        # A list of scanners found. Each element is a tuple with an index, the type of scanner, and the IPv4Address or IPv6Address object representing the IP address.

        for scanners in conn.scanners.list():
            if DEBUG:
                print("Scanner info:",scanners)
                #last_connect
                #type: "managed"= Nessus scanner, "managed_pvs"= NNM
            #So the scanner list does not return IP addresses.  There would need to be a way to match the scanner from this list to the scan data.
            #possible variables include 'id', 'key','name', 'uuid','remote_uuid',
            #tenabledata['scanners'] = MergeScanners(tenabledata['scanners'], ipaddress.IPv4Address(scanner))



    if DEBUG:
        print("\n\n\n")
        print("Scanners found:",tenabledata['scanners'])
        print("\n\n\n")

    exit()



#Takes the subnets and merges them, ensuring no duplicates between the two
#The orig should be a list of subnets (i.e. IPv4Network types)
#the new should be an IPv4Network type
def MergeSubnets(orig,new):

    FOUND=False
    for i in orig:
        (index,subnet)=i
        if subnet == new:
            FOUND=True

    #If we didn't find a match, then add it to the orig
    if FOUND == False:
        orig.append(tuple([len(orig), new]))

    return(orig)



#Takes the scanner and merges it to the existing Nessus scanner list, ensuring no duplicates between the two
#The orig should be a list of scanners (i.e. IPv4Addres types)
#the new should be an IPv4Address or IPv6Address type
def MergeScanners(orig,new):

    FOUND=False
    for i in orig:
        (index,sensortype,scanner)=i
        if scanner == new:
            FOUND=True

    #If we didn't find a match, then add it to the orig
    if FOUND == False:
        orig.append(tuple([len(orig), "scanner",new]))

    return(orig)

#Takes the scanner and merges it to the existing Nessus Network Monitor list, ensuring no duplicates between the two
#The orig should be a list of scanners (i.e. IPv4Addres types)
#the new should be the endpoint host that was detected by a Nessus Network Monitor.
#    Since we don't care about the IP address of the Network Monitor, we just care about which subnets it's monitoring.
def MergeNetworkMonitor(orig,new):

    FOUND=False
    for i in orig:
        (index,sensortype,endpoint)=i
        if endpoint == new:
            FOUND=True

    #If we didn't find a match, then add it to the orig
    if FOUND == False:
        orig.append(tuple([len(orig), "monitor",new]))

    return(orig)

#Takes the gateways and merges them, ensuring no duplicates between the two
#The orig should be a list of gateways (i.e. IPv4Address types with a /32)
#the new should be an IPv4Address or IPv6Address type
def MergeGateways(DEBUG,orig,new):
    FOUND=False
    if DEBUG:
        print("Checking if gateway",new,"already exists in the gateway list:",orig,"\n\n\n")
    for i in orig:
        (index,gw)=i
        if gw == new:
            FOUND=True
            if DEBUG:
                print("The gateway already exists, so do not add to the list of gateways.")

    #If we didn't find a match, then add it to the orig
    if FOUND == False:
        orig.append(tuple([len(orig), new]))
        if DEBUG:
            print("The gateway does not exist, so adding to the list of gateways.")

    return(orig)


#Takes two gw/subnet tuples (entry1 and entry2), and merges it into the router list
#If another duplicate exists, then merge the data together.
def MergeRouters(DEBUG,routers,entry1, entry2):
    FOUND=False
    if DEBUG:
        print("Checking for other router entries that have either of these subnets",entry1, entry2)

    # routers is a list of routing devices.  Each element is a tuple with an index, a list of gateways (IPv4Address and IPv6Address objects),
    #  and a list of subnets.  (IPv4Networks and IPv6Networks objects).

    (gw1,subnet1)=entry1
    (gw2,subnet2)=entry2

    #Special case, if this is the first entry into the routers, just add it.
    if len(routers) == 0:
        routers.append(tuple([0,[gw1,gw2],[subnet1,subnet2]]))
        if DEBUG:
            print("MergeRouters: No existing entries, so adding", entry1, entry2)
    else:
        MERGE = False
        if DEBUG:
            print("Searching through existing routers entries")
        for i in routers:
            if DEBUG:
                print(i)
            (index,gateways,subnets)=i
            #Does one of the new gateways already exist in this entry?
            for j in gateways:
                if j == gw1 or j == gw2:
                    if DEBUG:
                        print("Found a matching router entry by the gateway",gw1,gw2)
                    #Merge the new entries into this entry
                    MERGE=True
            #If an entry has not been found yet, keep searching by looking through the subnets
            if MERGE == False:
                for j in subnets:
                    if j == subnet1 or j == subnet2:
                        if DEBUG:
                            print("Found a matching router entry by the subnet",subnet1,subnet2)
                        #Merge the new entries into this entry
                        MERGE=True
            if MERGE == True:
                #This entry matches the new gateways and subnets, so let's merge everything together
                try:
                    x=gateways.index(gw1)
                except:
                    gateways.append(gw1)
                try:
                    x=gateways.index(gw2)
                except:
                    gateways.append(gw2)
                try:
                    x=subnets.index(subnet1)
                except:
                    subnets.append(subnet1)
                try:
                    x=subnets.index(subnet2)
                except:
                    subnets.append(subnet2)

                routers[index]=tuple([index,gateways,subnets])
                if DEBUG:
                    print("MergeRouters: Merging new router entry:",routers[index])
                break
        if MERGE == False:
            #Just add a new entry
            routers.append(tuple([len(routers), [gw1, gw2], [subnet1, subnet2]]))
            if DEBUG:
                print("MergeRouters: No existing entry for",entry1, entry2, "so adding")

    return(routers)

#Takes the routes and merges them, ensuring no duplicates between the two
#The orig should be a list of routes (i.e. A tuple of an IPv4Network and an IPv4Address)
#the newnet should be an IPv4Network or IPv6Network
#the newgw should be an IPv4Address or IPv6Address
def MergeRoutes(orig,newnet,newgw):

    FOUND=False
    for i in orig:
        (index,subnet,gw)=i
        if subnet == newnet and gw == newgw:
            FOUND=True

    #If we didn't find a match, then add it to the orig
    if FOUND == False:
        orig.append(tuple([len(orig), newnet, newgw]))

    return(orig)




#Gathers subnet info from either SecurityCenter or Tenable.io from Plugin 24272
def GetPlugin24272(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age):
    if DEBUG:
        print("Parsing information from all plugin ID 24272")

    TIO=False
    if str(type(conn))  == "<class 'tenable.io.TenableIO'>":
        TIO=True

    try:
        if TIO:
            results=conn.workbenches.vuln_outputs(24272,age=int(age))
        else:
            if age == None:
                results = conn.analysis.vulns(('pluginID', '=', '24272'), tool="vulndetails")
            else:
                results = conn.analysis.vulns(('pluginID', '=', '24272'),('lastSeen', '=', '00:' + str(age)), tool="vulndetails")
    except:
        results=[]
        print("Error getting output from 24272", sys.exc_info()[0], sys.exc_info()[1])


    for i in results:
        if DEBUG:
            print("Result info:",i)
        if TIO:
            tenabledata=ParsePlugin24272(DEBUG,i['plugin_output'],tenabledata,EXCLUDEPUBLIC)
        else:
            tenabledata=ParsePlugin24272(DEBUG,i['pluginText'],tenabledata,EXCLUDEPUBLIC)

    if DEBUG:
        print("Summary of information collected from  Plugin 24272\n")
        for i in tenabledata:
            print(i)
            print(tenabledata[i],"\n")

    return(tenabledata)




#Takes the text which should be from a Plugin Output for Plugin ID 24272, and parses it.
#Merges the data with the existing subnets, gateways, and routes lists, and then returns those.
#Make sure we do not include anything from 169.254.0.0/16
def ParsePlugin24272(DEBUG,text,tenabledata,EXCLUDEPUBLIC):
    if DEBUG:
        print("Parsing plugin text from 24272",text)
    for i in re.findall("IPAddress/IPSubnet = ([0-9\.]*\/[0-9\.]*)",text,flags=re.IGNORECASE+re.MULTILINE):
        if DEBUG:
            print("Subnet found:",i)
    pattern=re.compile("Routing Information")

    try:
        (ifaceinfo,routeinfo)=pattern.split(text,maxsplit=2)
    except:
        routeinfo=""
    if DEBUG:
        print("Route info section:",routeinfo)

    defaultroute = ipaddress.ip_network("0.0.0.0/0.0.0.0")
    for i in re.findall("[\s]+([\.0-9]+[\s]+[\.0-9]+[\s]+[\.0-9]+)",routeinfo,flags=re.IGNORECASE):
        if DEBUG:
            print("Subnet info from route info: \""+str(i)+"\"")
        (subnet,netmask,gw)=re.split(r'\s+', i,maxsplit=2)
        if DEBUG:
            print("Done split:")
            print("Subnet:",subnet)
            print("Netmask:",netmask)
            print("Gateway:",gw,"\n")
        n1 = ipaddress.ip_network(subnet+"/"+netmask,strict=False)
        if (not n1.is_multicast)  and (not n1.is_loopback) and (not n1.is_reserved) and (not n1.is_link_local) and (netmask != "255.255.255.255"):
            #Only save the route and subnet info if this is not a multicast, loopback, reserved,  or host
            if DEBUG:
                print("Saving subnet:",subnet)
            if n1 != defaultroute:
                if EXCLUDEPUBLIC == False or (EXCLUDEPUBLIC == True and n1.is_private ):
                    tenabledata['subnets'] = MergeSubnets(tenabledata['subnets'], n1)
            if not gw=="0.0.0.0":
                #Only save the gateway and route if the gateway is not 0.0.0.0
                tenabledata['gateways'] = MergeGateways(DEBUG, tenabledata['gateways'], ipaddress.IPv4Address(gw))
                tenabledata['routes'] = MergeRoutes(tenabledata['routes'], n1,ipaddress.IPv4Address(gw))

    if DEBUG:
        print("Summary of information collected after parsing output from 24272")
        print("Subnets:",tenabledata['subnets'])
        print("Gateways:",tenabledata['gateways'])
        print("Routes:",tenabledata['routes'])
        print("\n\n\n")

    return(tenabledata)


#Gathers subnet info from SecurityCenter or Tenable.io from Plugin 10663
def GetPlugin10663(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age):
    if DEBUG:
        print("Parsing information from all plugin ID 10663")

    #Assume we're using a SecurityCenter connection unless we know the connection is for Tenable.io
    TIO=False
    if str(type(conn))  == "<class 'tenable.io.TenableIO'>":
        TIO=True

    try:
        if TIO:
            results=conn.workbenches.vuln_outputs(10663,age=int(age))
        else:
            if age == None:
                results = conn.analysis.vulns(('pluginID', '=', '10663'), tool="vulndetails")
            else:
                results = conn.analysis.vulns(('pluginID', '=', '10663'),('lastSeen', '=', '00:' + str(age)), tool="vulndetails")
    except:
        results=[]
        print("Error getting plugin info", sys.exc_info()[0], sys.exc_info()[1])

    for i in results:
        if DEBUG:
            print("Result info:",i)
        if TIO:
            tenabledata = ParsePlugin10663(DEBUG, i['plugin_output'], tenabledata,EXCLUDEPUBLIC)
        else:
            tenabledata=ParsePlugin10663(DEBUG,i['pluginText'],tenabledata,EXCLUDEPUBLIC)

    if DEBUG:
        print("Summary of information collected from  Plugin 10663\n")
        for i in tenabledata:
            print(i)
            print(tenabledata[i],"\n")

    return(tenabledata)


#Takes the text which should be from a Plugin Output for Plugin ID 10663, and parses it.
#Merges the data with the existing subnets, gateways, and routes lists, and then returns those.
def ParsePlugin10663(DEBUG,text,tenabledata,EXCLUDEPUBLIC):
    if DEBUG:
        print("Parsing plugin text from 10663",text)
    gw=""
    for i in re.findall("Router : ([0-9\.]+)",text,flags=re.IGNORECASE+re.MULTILINE):
        if DEBUG:
            print("Router found:",i)
        gw=i
        tenabledata['gateways'] = MergeGateways(DEBUG,tenabledata['gateways'], ipaddress.IPv4Address(gw))

    netmask=""
    for i in re.findall("Netmask : ([0-9\.]+)",text,flags=re.IGNORECASE+re.MULTILINE):
        if DEBUG:
            print("Netmask found:",i)
        netmask=i

    ipaddr=""
    for i in re.findall("IP address the DHCP server would attribute us : ([0-9\.]+)",text,flags=re.IGNORECASE+re.MULTILINE):
        if DEBUG:
            print("IP address found:",i)
        ipaddr=i

    if ipaddr != "" and netmask != "":
        s1 = ipaddress.ip_network(ipaddr+"/"+netmask,strict=False)
        if EXCLUDEPUBLIC == False or (EXCLUDEPUBLIC == True and s1.is_private):
            tenabledata['subnets']=MergeSubnets(tenabledata['subnets'],s1)
        if gw != "":
            tenabledata['routes']=MergeRoutes(tenabledata['routes'],s1,ipaddress.IPv4Address(gw))


    return(tenabledata)


#Gathers subnet info from SecurityCenter or Tenable.io from Plugin 10287
def GetPlugin10287(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age):
    if DEBUG:
        print("Parsing information from all plugin ID 10287")

    #Assume we're using a SecurityCenter connection unless we know the connection is for Tenable.io
    TIO=False
    if str(type(conn))  == "<class 'tenable.io.TenableIO'>":
        TIO=True

    try:
        if TIO:
            results=conn.workbenches.vuln_outputs(10287,age=int(age))
        else:
            if age == None:
                results = conn.analysis.vulns(('pluginID', '=', '10287'), tool="vulndetails")
            else:
                results = conn.analysis.vulns(('pluginID', '=', '10287'),('lastSeen', '=', '00:' + str(age)), tool="vulndetails")
    except:
        results=[]
        print("Error getting plugin info", sys.exc_info()[0], sys.exc_info()[1])

    for i in results:
        if DEBUG:
            print("Result info:",i)
        if TIO:
            tenabledata = ParsePlugin10287(DEBUG, i['plugin_output'], tenabledata,EXCLUDEPUBLIC)
        else:
            tenabledata=ParsePlugin10287(DEBUG,i['pluginText'],tenabledata,EXCLUDEPUBLIC)

    if DEBUG:
        print("Summary of information collected from  Plugin 10287\n")
        for i in tenabledata:
            print(i)
            print(tenabledata[i],"\n")

    return(tenabledata)


#Takes the text which should be from a Plugin Output for Plugin ID 10287, and parses it.
#Merges the data with the existing subnets, gateways, and routes lists, and then returns those.
#TODO: Make this work with IPv6 as well
def ParsePlugin10287(DEBUG,text,tenabledata,EXCLUDEPUBLIC):
    #First, split the plugin output.
    #Assumptions:
    # First line will always be "For your information, here is the traceroute from"...
    #The last 4 lines will be the endhost blank line, the "Hop Count Line", and another blank line
    # The remaining lines will be IP addresses or possibly symbols like (?) until the "Hop Count line"
    # The first IP address will always be the scanner.
    if DEBUG:
        print("Parsing plugin text from 10287\n",text)


    FOUNDINFO=False
    FOUNDHOP=False
    FIRSTHOP=True
    previoushop=None
    IGNOREPUBLIC=False

    lines=re.split("\n",text)
    gwlist=[]
    if DEBUG:
        print("Total lines found:",len(lines))
    scanner=""
    endhost=""
    for i in range(0,len(lines)):
        #If we have not already see the "For your information" line, look for it.
        if DEBUG:
            print("Next line to examine \""+str(lines[i])+"\"")
        if FOUNDINFO == False:
            if DEBUG:
                print("Is this the \"For your information \" line?")
            try:
                for (scanner, endhost) in re.findall("For your information, here is the traceroute from (.*) to (.*) :", lines[i], flags=re.IGNORECASE):
                    if DEBUG:
                        print("The scanner IP address is: \"" + str(scanner) + "\"")
                        print("The target address is: \"" + str(endhost) + "\"")
                    tenabledata['scanners'] = MergeScanners(tenabledata['scanners'], ipaddress.IPv4Address(scanner))
                    FOUNDINFO=True
                    if EXCLUDEPUBLIC == True and not ipaddress.IPv4Address(scanner).is_private:
                        IGNOREPUBLIC=True

                    if EXCLUDEPUBLIC == True and not ipaddress.IPv4Address(endhost).is_private:
                        IGNOREPUBLIC=True
                if IGNOREPUBLIC:
                    #This is a traceroute involving public endpoints, so ignore
                    break
            except:
                    print("Error parsing ",lines[i])
                    print(sys.exc_info()[0], sys.exc_info()[1])
        elif FOUNDHOP == True and lines[i] == "":
            #Still need to check since the last hop might not respond
            if DEBUG:
                print("End of the hop list found.")
            break
        elif FOUNDHOP == False or (FOUNDHOP == True and i != ""):
            if DEBUG:
                print("Is this a hop?")
            #If we are here, we have yet to find the first hop, or is has been found and we are in the hop list
            #First, see if we have found a hop yet.
            if lines[i] == scanner:
                #We don't care about the first hop because that's the scanner
                FOUNDHOP=True
                FIRSTHOP=False
                previoushop=ipaddress.IPv4Address(scanner)
                if DEBUG:
                    print("Ignoring first hop")
            elif lines[i] == endhost:
                #We don't care about the last hop because that's the endpoint being scanned
                FOUNDHOP=True
                FIRSTHOP=False
                if DEBUG:
                    print("End of the hop list found.")
                break
            elif lines[i] == "?":
                if DEBUG:
                    print("Found hop that did not respond back")
                #We found a hop that didn't respond back.
                #If this is the first hop, don't bother adding it.
                #If not the first hop, then add a None to the gwlist.
                if FIRSTHOP == False:
                    gwlist.append(None)
                FOUNDHOP=True
                FIRSTHOP=False
                previoushop=None
            else:
                if DEBUG:
                    print("Attemping to parse line for hop data",lines[i])
                for j in re.findall("([0-9\.]+)", lines[i], flags=re.IGNORECASE):
                    #We found a hop
                    if DEBUG:
                        print("The next hop is : \"" + str(j) + "\"")
                    try:
                        currenthop=ipaddress.IPv4Address(j)
                    except:
                        if DEBUG:
                            print("Not a valid next hop: \"" + str(j) + "\"")
                        currenthop=None
                    if previoushop == currenthop and currenthop != None:
                        print("Routing loop discovered")
                    else:
                        tenabledata['gateways'] = MergeGateways(DEBUG, tenabledata['gateways'], ipaddress.IPv4Address(j))
                        gwlist.append(ipaddress.IPv4Address(j))
                    FOUNDHOP = True
                    FIRSTHOP = False
                    previoushop=currenthop
        else:
            print("Unknown state in parsing plugin 10287",text)

    #Only add the traceroute data if there is actually a router involved.
    #It is unnecessary to include every bit of traceroute between hosts on the same subnet.
    if len(gwlist) > 0:
        if DEBUG:
            print("Adding this traceroute:",gwlist)
            print("Total hops for this traceroute:",len(gwlist))
        tenabledata['traceroutes'].append(tuple([len(tenabledata['traceroutes']),scanner,endhost,gwlist]))

    if DEBUG:
        print("Summary of information collected after parsing one instance of Plugin 10287")
        print("Gateways:",tenabledata['gateways'])
        print("Traceroutes:",tenabledata['traceroutes'])
        print("\n\n\n")

    return(tenabledata)



#Gathers subnet info from SecurityCenter or Tenable.io from Plugin 10287
def GetPlugin12(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age):
    if DEBUG:
        print("Parsing information from all plugin ID 12")

    #Assume we're using a SecurityCenter connection unless we know the connection is for Tenable.io
    TIO=False
    if str(type(conn))  == "<class 'tenable.io.TenableIO'>":
        TIO=True

    try:
        if TIO:
            results=conn.workbenches.vuln_outputs(12,age=int(age))
        else:
            if age == None:
                results = conn.analysis.vulns(('pluginID', '=', '12'), tool="vulndetails")
            else:
                results = conn.analysis.vulns(('pluginID', '=', '12'),('lastSeen', '=', '00:' + str(age)), tool="vulndetails")
    except:
        results=[]
        print("Error getting plugin info", sys.exc_info()[0], sys.exc_info()[1])

    for i in results:
        if DEBUG:
            print("Result info:",i)
        if TIO:
            tenabledata = ParsePlugin12(DEBUG, i['plugin_output'], tenabledata,EXCLUDEPUBLIC)
        else:
            tenabledata=ParsePlugin12(DEBUG,i['pluginText'],tenabledata,EXCLUDEPUBLIC)

    if DEBUG:
        print("Summary of information collected from  Plugin 12\n")
        for i in tenabledata:
            print(i)
            print(tenabledata[i],"\n")

    return(tenabledata)



#Takes the text which should be from a Plugin Output for Plugin ID 12, and parses it.
#Merges the data with the existing Nessus Network Monitors
#TODO: Make this work with IPv6 as well
def ParsePlugin12(DEBUG,text,tenabledata,EXCLUDEPUBLIC):
    if DEBUG:
        print("Parsing plugin text from 12\n",text)

    lines=re.split("\n",text)
    if DEBUG:
        print("Total lines found:",len(lines))
    for i in range(0,len(lines)):
        #We only care about finding NNMs that are 0 hops away from the target, otherwise we don't know which subnet the NNM is on
        for (endhost) in re.findall("The remote host (.*) is 0 hops away from a NNM sensor", lines[i], flags=re.IGNORECASE):
            if DEBUG:
                print("NNM found \"" + str(endhost) + "\"")
            try:
                ip=ipaddress.IPv4Address(endhost)
            except:
                ip = ipaddress.IPv6Address(endhost)

            if not ip.is_link_local and not ip.is_loopback and not ip.is_reserved and not ip.is_multicast:
                if EXCLUDEPUBLIC == False or (EXCLUDEPUBLIC == True and ip.is_private):
                    tenabledata['scanners'] = MergeNetworkMonitor(tenabledata['scanners'], ip)

    if DEBUG:
        print("Summary of endpoints detected by NNM found by Plugin 12")
        print("Scanners:",tenabledata['scanners'])
        print("\n\n\n")

    return(tenabledata)




def AnalyzeRouters(DEBUG,tenabledata):
    if DEBUG:
        print("Reviewing plugin ID 10287 along with subnets and gateways to determine routers")

    gwsubnetlist=[]
    #First go through all the gateways and match them with their associated subnets
    # A list of gateways found.  Each element is a tuple with the an index and the IPv4Address or IPv6Address object representing the gateway.
    if DEBUG:
        print("Gateways:",tenabledata['gateways'])

    for i in tenabledata['gateways']:
        (gwi,gwaddr)=i
        # A list of subnets found.  Each element is a tuple with the an index and the IPv4Network or IPv6Network object representing the subnet.
        SNFOUND=False
        for j in tenabledata['subnets']:
            (subneti,subnet)=j

            if subnet.overlaps(ipaddress.ip_network(str(gwaddr) + "/32")):
                gwsubnetlist.append(tuple([gwaddr,subnet]))
                SNFOUND=True
        if SNFOUND==False:
            if DEBUG:
                print("There was no subnet found for the gateway",gwaddr)
            gwsubnetlist.append(tuple([gwaddr, None]))

    #Now go through all the subnets and to catch all the subnets that might not have gateways discovered.
    for i in tenabledata['subnets']:
        (subneti, subnet) = i
        GWFOUND=False
        for j in tenabledata['gateways']:
            (gwi, gwaddr) = j
            if subnet.overlaps(ipaddress.ip_network(str(gwaddr) + "/32")):
                GWFOUND=True
        if GWFOUND == False:
            if DEBUG:
                print("There was no gateway found for the subnet",subnet)
            gwsubnetlist.append(tuple([None,subnet]))

    if DEBUG:
        print("List of gateways and their subnets:",gwsubnetlist)
        print("Next, analyze which subnets share a gateway")



    #Parse all the traceroute results and use that to start matching up subnets.
    # This may not match everything, so afterwards all the subnets and gateways must be re-examined and compared to the routers.
    for (tri,scanner,endhost,gwlist) in tenabledata['traceroutes']:
        #tenabledata['traceroutes'].append(tuple([len(tenabledata['traceroutes']),scanner,endhost,gwlist]))
        if len(gwlist) == 1:
            if DEBUG:
                print("This router shares two subnets:", gwlist)
                print("Match this scanner and endhost to the gwsubnetlist:", scanner, endhost)

            entry1 = None
            entry2 = None
            # Find a match with the scanner
            for i in gwsubnetlist:
                (gw, subnet) = i
                # We only care if the entry has both a gateway and subnet, otherwise we cannot do anything with it for now.
                if gw != None and subnet != None:
                    if subnet.overlaps(ipaddress.ip_network(str(scanner) + "/32")):
                        # We found the gwsubnetlist entry for the scanner, so save it and find the matching entry for the endhost
                        entry1 = i
            # Find a match with the endhost
            for i in gwsubnetlist:
                (gw, subnet) = i
                # We only care if the entry has both a gateway and subnet, otherwise we cannot do anything with it for now.
                if gw != None and subnet != None:
                    if subnet.overlaps(ipaddress.ip_network(str(endhost) + "/32")):
                        # We found the gwsubnetlist entry for the endhost
                        entry2 = i
            if entry1 != None and entry2 != None:
                if DEBUG:
                    print("These two subnets share a router:", entry1, entry2)
                try:
                    tenabledata['routers'] = MergeRouters(DEBUG, tenabledata['routers'], entry1, entry2)
                except:
                    if DEBUG:
                        print("Not a valid next hop: \"" + str(lines[i]) + "\"")

    if DEBUG:
        print("Here are the routers:",tenabledata['routers'])


    #Now lets add any subnets or gateways that do not share any routers.
    for (gw,subnet) in gwsubnetlist:
        SUBNETFOUND=False
        if subnet != None:
            if DEBUG:
                print("Checking if subnet",subnet,"already has an entry on a router")
            for (ri,gwlist,snlist) in tenabledata['routers']:
                if DEBUG:
                    print("Checking for subnet",subnet,"in subnet list",snlist)
                try:
                    x=snlist.index(subnet)
                    SUBNETFOUND = True
                except:
                    x=None
            if SUBNETFOUND == False:
                if DEBUG:
                    print("This subnet was not found on any existing router entry, so adding an entry for",gw,subnet)
                tenabledata['routers'].append(tuple([len(tenabledata['routers']),[gw],[subnet]]))
            else:
                if DEBUG:
                    print("This subnet already exists in a router entry, so not adding")

    return(tenabledata)


#If there is Tenable asset data that matches one or more IP addresses on a router,
# then we can use that asset data to fill in information on any additional interfaces that we don't know about
def MatchRoutersToAssets(DEBUG,tenabledata):
    # A list of assets found.  Each element is a tuple with an index, an asset ID, and a list of  IPv4Address and IPv6Address objects.
    #tenabledata['assets'] = []

    # A list of routing devices.  Each element is a tuple with an index, a list of gateways (IPv4Address and IPv6Address objects),
    #  and a list of subnets  (IPv4Networks and IPv6Networks objects).
    # This should all be calculated from the data from Tenable.
    #tenabledata['routers'] = []

    #Go through all routers
    for (index,gateways,subnets) in tenabledata['routers']:
        #For each router, pull out the individual IP addresses
        for i in gateways:
            #Check if the IP address matches any one of the asset IP addresses.
            for (index,id,ipaddresses) in tenabledata['assets']:
                for j in ipaddresses:
                    if i == j:
                        if DEBUG:
                            print("Matched the router with the IP",gateways,"to asset ID",id)




    return(tenabledata)



def SetJSONDefault(obj):
    if isinstance(obj,ipaddress.IPv4Address):
        return str(obj)
    if isinstance(obj,ipaddress.IPv6Address):
        return str(obj)
    if isinstance(obj,ipaddress.IPv4Network):
        return str(obj)
    if isinstance(obj,ipaddress.IPv6Network):
        return str(obj)
    print("Need handler for object type",type(obj))
    raise TypeError


#Gathers subnet info from either SecurityCenter or Tenable.io from Plugin 24272
def DumpPluginsToFile(DEBUG,outfp,tenabledata):
    if DEBUG:
        print("Downloading all plugin information to a file")

    try:
        json.dump(tenabledata,outfp,default=SetJSONDefault)
    except:
        print("Error writing data to json", sys.exc_info()[0], sys.exc_info()[1])
        return(False)

    return(True)

def ParseOfflineFile(DEBUG,offlinefile):
    if offlinefile == None:
        return(False)

    infp=open(offlinefile,"r")
    tenabledata=json.load(infp)
    infp.close()
    print(tenabledata)

    x=[]
    for i in tenabledata['ipaddresses']:
        try:
            x.append(ipaddress.IPv4Address(i))
        except:
            x.append(ipaddress.IPv6Address(i))
    tenabledata['ipaddresses']=x

    x=[]
    for i in tenabledata['assets']:
        (a,b,c)=i
        y=[]
        for j in c:
            try:
                y.append(ipaddress.IPv4Address(j))
            except:
                y.append(ipaddress.IPv6Address(j))
        x.append(tuple([a,b,y]))
    tenabledata['assets']=x

    x = []
    for i in tenabledata['subnets']:
        (a, b) = i
        try:
            x.append(tuple([a,ipaddress.IPv4Network(b)]))
        except:
            x.append(tuple([a,ipaddress.IPv6Network(b)]))
    tenabledata['subnets']=x

    x = []
    for i in tenabledata['gateways']:
        (a, b) = i
        try:
            x.append(tuple([a,ipaddress.IPv4Address(b)]))
        except:
            x.append(tuple([a,ipaddress.IPv6Address(b)]))
    tenabledata['gateways']=x

    x=[]
    for i in tenabledata['routes']:
        (a,b,c)=i
        try:
            gw=ipaddress.IPv4Network(j)
        except:
            gw=ipaddress.IPv6Network(j)
        try:
            subnet=ipaddress.IPv4Address(j)
        except:
            subnet=ipaddress.IPv6Address(j)

        x.append(tuple([a,gw,subnet]))
    tenabledata['routes']=x

    x = []
    for i in tenabledata['scanners']:
        (a,b,c) = i
        try:
            x.append(tuple([a,b,ipaddress.IPv4Address(c)]))
        except:
            x.append(tuple([a,b,ipaddress.IPv6Address(c)]))
    tenabledata['scanners']=x

    outfp=open("test.txt","w")
    DumpPluginsToFile(DEBUG,outfp,tenabledata)
    outfp.close

    return(tenabledata)

def GatherInfo(DEBUG,outputfile,conn,tenabledata,EXCLUDEPUBLIC,age):
    print("Starting information gathering.")

    tenabledata=DownloadAssetInfoIO(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age)

    #tenabledata=DownloadScanners(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age)


    #Gather interface enumeration
    tenabledata=GetPlugin24272(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age)

    #Gather information on NNM detections
    tenabledata=GetPlugin12(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age)

    #Gather info from DHCP
    tenabledata=GetPlugin10663(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age)

    #Gather traceroute info.
    # This should also provide the information on a Nessus scanner itself, since the first IP will be the scanner.
    tenabledata=GetPlugin10287(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age)


    # 10551 gives some clues to interfaces via SNMP.  This could potentially be used to make a routing map

    #92370 shows ARP tables, so important for matching MAC addresses to IP addresses.


    #Plugin ID 12 can sometimes provide information about other IP or MAC addresses on the system.
    # (i.e. 192.168.15.1 belongs to 192.168.16.1 because this plugin says so, and the hostname is the same)

    #Need a plugin to get subnet data from Windows and Linux

    #52616

    #10180 could be used to determine how big the local subnet is for the Nessus scanner, if there are no other options.
    #If this plugin has "Hardware address : " in the output text, you know it is on the same subnet as the scanner.  This would need the scanner info from 19506 as well.


    #Plugin ID 19 can show that there are multiple VLANs on a host, potentially indicating a gateway

    #56310 can show some network information from the iptables, but this may not indicate actual network subnets.
    #It may be more zones.

    #25203 for linux system IP address info

    #35716 gives important information on MAC address matches for assets.

    #TODO: Need a function that takes data such as traceroute info, and pieces together what gateways might be connected.


    if DEBUG:
        print("Summary of information collected from all plugins\n")
        for i in tenabledata:
            print(i)
            print(tenabledata[i],"\n")

    if outputfile != None:
        outfp=open(outputfile,"w")
        DumpPluginsToFile(DEBUG,outfp,tenabledata)
        outfp.close

    return(tenabledata)


#Attempts to make a connection to Tenable.sc
def ConnectSC(DEBUG,username,password,host,port):
    #Create the connection to Tenable.sc
    try:
        sc = TenableSC(host, port=port)
    except:
        print("Error connecting to SecurityCenter", sys.exc_info()[0], sys.exc_info()[1])
        return(False)

    try:
        sc.login(username, password)
    except:
        print("Error logging into to SecurityCenter", sys.exc_info()[0], sys.exc_info()[1])
        if DEBUG:
            print("Username:",username)
        return (False)

    return(sc)


#Attempts to make a connection to Tenable.io
def ConnectIO(DEBUG,accesskey,secretkey,host,port):
    #Create the connection to Tenable.io
    try:
        tio=TenableIO(accesskey, secretkey)
    except:
        print("Error connecting to Tenable.io")
        return(False)

    return(tio)

#subnet should be an IPv4Network or IPv6Network object
def CalculateHostsInSubnet(DEBUG,subnet,tenabledata):
    ipcount=0
    for i in tenabledata['ipaddresses']:
        if isinstance(i,ipaddress.IPv4Address):
            if subnet.overlaps(ipaddress.IPv4Network(str(i)+"/32")):
                if DEBUG:
                    print("IP addresss",i,"is part of subnet",subnet,"so adding to count")
                ipcount+=1
        elif isinstance(i,ipaddress.IPv6Address):
            if subnet.overlaps(ipaddress.IPv6Network(str(i)+"/128")):
                if DEBUG:
                    print("IP addresss",i,"is part of subnet",subnet,"so adding to count")
                ipcount+=1

    return(ipcount)


def CreateMapPlotRouters(DEBUG,tenabledata,age,IGNOREEMPTYSUBNETS):
    # build a blank graph
    G = nx.Graph()
    y=1
    x=0.1
    subnetyoffset=0.7


    if len(tenabledata['routers']) >= 6:
        graphwidth=160*len(tenabledata['routers'])/2
        graphheight=160*len(tenabledata['routers'])
        xrange=len(tenabledata['routers'])/2
        yrange=len(tenabledata['routers'])
    else:
        graphwidth=480
        graphheight=960
        xrange=3
        yrange=6

    #Keep track of how far to the right we use the X-axis
    maxxusage=3.2

    data = []
    layout = {
        'xaxis': {
            'range': [0, xrange],
            'visible': False,
            'showline': False,
            'zeroline': True,
        },
        'showlegend': False,
        'yaxis': {
            'range': [0, yrange],
            'visible': False,
            'showline': False,
            'zeroline': True,
        },
        'width': graphwidth,
        'height': graphheight,
        'shapes': [],
        'title': '<br>Network Diagram',
        'titlefont': dict(size=16),
        'hovermode': 'closest',
        'margin': dict(b=20, l=5, r=5, t=40),
        'annotations': [dict(
            text="Total IP addresses analyzed: "+str(len(tenabledata['ipaddresses'])),
            showarrow=False,
            yref="paper",
            x=xrange/2, y=0.002),
            dict(
                text="Generated by <a href='https://github.com/cybersmithio/networkmapper'> networkmapper.py</a>",
                showarrow=False,
                xref="paper", yref="paper",
                x=0.005, y=-0.002)
        ],
    }

    if age != None:
        layout['title']=layout['title']+'<br>Showing assets seen in the last '+str(age)+' days<br>'

    if DEBUG:
        print("Plot layout height:",layout['height'])
        print("Plot layout width:",layout['width'])


    #Go through all the routers and put a node on the graph
    for (index,gwlist,snlist) in tenabledata['routers']:
        subnetcount=0

        #Plot each subnet that will be attached to this router
        subnetx=x
        subnety=y
        for subnet in snlist:
            #Set a flag if this subnet has an NNM
            NNM=False

            hostsinsubnet=CalculateHostsInSubnet(DEBUG,subnet,tenabledata)
            if IGNOREEMPTYSUBNETS == False or (IGNOREEMPTYSUBNETS == True and hostsinsubnet > 0):
                subnetcount+=1
                #Draw the subnet
                (text, shapeinfo) = PlotSubnetShape(DEBUG, subnetx + 1, subnety + 0.25, str(subnet)+"   IP addresses:"+str(hostsinsubnet))
                for i in shapeinfo:
                    layout['shapes'].append(i)
                for i in text:
                    data.append(i)

                #Connect the subnet to the router
                (shapeinfo) = DrawElbowConnector(DEBUG, subnetx + 1, subnety + 0.3, subnetx + 0.7, subnety + 0.3, subnetx + 0.7, y+0.3, x+0.5, y+0.3)

                #(shapeinfo) = DrawStraightConnector(DEBUG, subnetx + 0.7, subnety + 0.3, x + 0.5, y + 0.3)
                for i in shapeinfo:
                    layout['shapes'].append(i)


                #Try to attach any scanners to the subnet, so check all the scanners
                scannercount=0
                for(index,sensortype,ns) in tenabledata['scanners']:
                    if sensortype == "scanner":
                        #See if this gateway is in the current subnet, and if so, print the name
                        if subnet.overlaps(ipaddress.ip_network(str(ns)+"/32")):
                            if maxxusage < subnetx+3.1+(scannercount*0.7):
                                maxxusage=subnetx+3.1+(scannercount*0.7)
                            (text, shapeinfo) = PlotNessusScanner(DEBUG, subnetx+3.1+(scannercount*0.7), subnety-0.2, ns)
                            for i in shapeinfo:
                                layout['shapes'].append(i)
                            for i in text:
                                data.append(i)
                            #Draw a connector from the scanner to the subnet
                            #(shapeinfo) = DrawElbowConnector(DEBUG, subnetx+1.3, subnety+0.25, subnetx+1.3, subnety+0.15, subnetx+2.25+(scannercount*0.7), subnety+0.15,subnetx+2.25+(scannercount*0.7) , subnety+0.1)
                            (shapeinfo) = DrawRightAngleConnector(DEBUG, subnetx+2.65, subnety+0.3, subnetx+3+(scannercount*0.7), subnety+0.3, subnetx+3+(scannercount*0.7) , subnety+0.22)
                            for i in shapeinfo:
                                layout['shapes'].append(i)

                            scannercount+=1
                    elif sensortype == "monitor" and NNM == False:
                        if DEBUG:
                            print("Checking if network monitor needs to be draw")
                        if subnet.overlaps(ipaddress.ip_network(str(ns)+"/32")):
                            if maxxusage < subnetx+3.1+(scannercount*0.7):
                                maxxusage=subnetx+3.1+(scannercount*0.7)
                            (text, shapeinfo) = PlotNessusNetworkMonitor(DEBUG, subnetx+3.1+(scannercount*0.7), subnety-0.2, "")
                            for i in shapeinfo:
                                layout['shapes'].append(i)
                            for i in text:
                                data.append(i)
                            # Draw a connector from the scanner to the subnet
                            # (shapeinfo) = DrawElbowConnector(DEBUG, subnetx+1.3, subnety+0.25, subnetx+1.3, subnety+0.15, subnetx+2.25+(scannercount*0.7), subnety+0.15,subnetx+2.25+(scannercount*0.7) , subnety+0.1)
                            (shapeinfo) = DrawRightAngleConnector(DEBUG, subnetx + 2.65, subnety + 0.3, subnetx + 3 + (scannercount * 0.7), subnety + 0.3, subnetx + 3 + (scannercount * 0.7), subnety + 0.22)
                            for i in shapeinfo:
                                layout['shapes'].append(i)
                            NNM=True
                            scannercount += 1

                subnety+=subnetyoffset
        #See if there were any subnets for this router.
        if subnetcount > 0:
            #Plot the router and merge into the plot data
            (text, shapeinfo) = PlotRouterShape(DEBUG, x, y, gwlist)
            for i in shapeinfo:
                layout['shapes'].append(i)
            for i in text:
                data.append(i)
            y=y+(len(snlist)*subnetyoffset)
        else:
            if DEBUG:
                print("Not putting this router on since it has no subnets to draw")


    layout['xaxis'] = {
        'range': [0, maxxusage+0.5],
        'visible': False,
        'showline': False,
        'zeroline': True,
    }
    layout['yaxis'] =  {
        'range': [0, y+1],
        'visible': False,
        'showline': False,
        'zeroline': True,
    }
    layout['width']=(maxxusage+0.5)*160
    layout['height']=(y+1)*160

    fig = go.Figure(data=data,layout=layout)



    # Open the graph in a browser window
    plotly.offline.plot(fig, auto_open=True)



#
#This map draws an individual subnet, all aligned along 0 on the X-axis,
# and each new subnet is an increment down the Y-axis.
# From the subnet, draw a line out and then 90 degrees down.
# From there, run a horizontal line across.  If there are any gateways,
# put them here, incrementing the X position.
# Also, if there are hosts, increment them along the X.
#
# The nodes are drawn separate from the connectors.
#
def CreateMapPlot(DEBUG,tenabledata,age):
    # build a blank graph
    G = nx.Graph()

    y=1
    x=0.1
    subnetyoffset=1
    maxxusage=2

    if len(tenabledata['routers']) >= 6:
        graphwidth=160*len(tenabledata['routers'])/2
        graphheight=160*len(tenabledata['routers'])
        xrange=len(tenabledata['routers'])/2
        yrange=len(tenabledata['routers'])
    else:
        graphwidth=480
        graphheight=960
        xrange=3
        yrange=6

    data = []
    layout = {
        'xaxis': {
            'range': [0, xrange],
            'visible': False,
            'showline': False,
            'zeroline': True,
        },
        'showlegend': False,
        'yaxis': {
            'range': [0, yrange],
            'visible': False,
            'showline': False,
            'zeroline': True,
        },
        'width': graphwidth,
        'height': graphheight,
        'shapes': [],
        'title': '<br>Network Diagram<br>Showing assets seen in the last '+str(age)+' days<br>Total IP addresses analyzed: '+str(len(tenabledata['ipaddresses'])),
        'titlefont': dict(size=16),
        'hovermode': 'closest',
        'margin': dict(b=20, l=5, r=5, t=40),
        'annotations': [dict(
            text="Generated by <a href='https://github.com/cybersmithio/networkmapper'> networkmapper.py</a>",
            showarrow=False,
            xref="paper", yref="paper",
            x=0.005, y=-0.002)],
    }

    #Go through all the subnets and put a node on the graph
    for (index,subnet) in tenabledata['subnets']:
        (text, shapeinfo) = PlotSubnetShape(DEBUG, x+0.7, y+0.25, str(subnet))
        for i in shapeinfo:
            layout['shapes'].append(i)
        for i in text:
            data.append(i)

        #Try to attach a gateway to each subnet, so check all the gateways
        gwtext=[]
        for(index,gw) in tenabledata['gateways']:
            #See if this gateway is in the current subnet, and if so, print the name
            if subnet.overlaps(ipaddress.ip_network(str(gw)+"/32")):
                gwtext.append(str(gw))
        (text, shapeinfo) = PlotGatewayShape(DEBUG, x, y, gwtext)
        for i in shapeinfo:
            layout['shapes'].append(i)
        for i in text:
            data.append(i)
        (shapeinfo)=DrawStraightConnector(DEBUG, x+0.7, y+0.3, x+0.5, y+0.3)
        for i in shapeinfo:
            layout['shapes'].append(i)

        #Try to attach any scanners to the subnet, so check all the scanners
        scannercount=0
        for(index,sensortype,ns) in tenabledata['scanners']:
            if sensortype == "scanner":
                #See if this gateway is in the current subnet, and if so, print the name
                if subnet.overlaps(ipaddress.ip_network(str(ns)+"/32")):
                    if maxxusage < x+2+(scannercount*0.7):
                        maxxusage = x+2+(scannercount*0.7)
                    (text, shapeinfo) = PlotNessusScanner(DEBUG, x+2+(scannercount*0.7), y-0.3, ns)
                    for i in shapeinfo:
                        layout['shapes'].append(i)
                    for i in text:
                        data.append(i)
                    #Draw a connector from the scanner to the subnet
                    (shapeinfo) = DrawElbowConnector(DEBUG, x+1, y+0.25, x+1, y+0.15, x+2.2+(scannercount*0.7), y+0.15,x+2.2+(scannercount*0.7) , y+0.1)
                    for i in shapeinfo:
                        layout['shapes'].append(i)

                    scannercount+=1
            elif sensortype == "monitor":
                if DEBUG:
                    print("Checking if network monitor needs to be draw")

        y=y+subnetyoffset

    layout['xaxis'] = {
        'range': [0, maxxusage+0.5],
        'visible': False,
        'showline': False,
        'zeroline': True,
    }
    layout['yaxis'] =  {
        'range': [0, y+1],
        'visible': False,
        'showline': False,
        'zeroline': True,
    }
    layout['width']=(maxxusage+0.5)*160
    layout['height']=(y+1)*160


    fig = go.Figure(data=data,
                    layout=layout)

    # Open the graph in a browser window
    plotly.offline.plot(fig, auto_open=True)


def CreateTestPattern(DEBUG):
    # build a blank graph
    G = nx.Graph()

    subnet_trace = go.Scatter(
        x=[],
        y=[],
        text=[],
        textposition='bottom center',
        hovertext=[],
        mode='markers+text',
        hoverinfo='none',
        marker=dict(
            showscale=True,
            # colorscale options
            # 'Greys' | 'YlGnBu' | 'Greens' | 'YlOrRd' | 'Bluered' | 'RdBu' |
            # 'Reds' | 'Blues' | 'Picnic' | 'Rainbow' | 'Portland' | 'Jet' |
            # 'Hot' | 'Blackbody' | 'Earth' | 'Electric' | 'Viridis' |
            colorscale='YlGnBu',
            reversescale=True,
            color=[],

            size=[],
            colorbar=dict(
                thickness=15,
                title='Node Connections',
                xanchor='left',
                titleside='right'
            ),
            line=dict(width=2)))


    layout = {
        'xaxis': {
            'range': [0, 4.5],
            'visible': False,
            'showline': False,
            'zeroline': True,
        },
        'showlegend': False,
        'yaxis': {
            'range': [0, 4.5],
            'visible': False,
            'showline': False,
            'zeroline': True,
        },
        'width': 800,
        'height': 800,
        'shapes': []
    }
    data=[]
    (text,shapeinfo)=PlotGatewayShape(DEBUG, 1, 1, ["xxx.xxx.xxx.1","xxx.xxx.xxx.2","xxx.xxx.xxx.xxx"])
    for i in shapeinfo:
        layout['shapes'].append(i)
    for i in text:
        data.append(i)

    (text,shapeinfo)=PlotSubnetShape(DEBUG,2,2,"xxx.xxx.xxx.xxx/xx")
    for i in shapeinfo:
        layout['shapes'].append(i)
    for i in text:
        data.append(i)


    (text,shapeinfo)=PlotNessusScanner(DEBUG,3,3,"xxx.xxx.xxx.xxx")
    for i in shapeinfo:
        layout['shapes'].append(i)
    for i in text:
        data.append(i)


    (text,shapeinfo)=PlotNessusNetworkMonitor(DEBUG,3.5,3,"xxx.xxx.xxx.xxx")
    for i in shapeinfo:
        layout['shapes'].append(i)
    for i in text:
        data.append(i)




    (shapeinfo)=DrawElbowConnector(DEBUG, 1, 3, 1, 3.2, 2, 3.2, 2, 3.5)
    for i in shapeinfo:
        layout['shapes'].append(i)




    fig = go.Figure(data=data,
                    layout=layout)

    #Open the graph in a browser window
    plotly.offline.plot(fig, auto_open=True)


def PlotShapeCircle(DEBUG):
    layout = {
        'xaxis': {
            'range': [0, 4.5],
            'zeroline': False,
        },
        'yaxis': {
            'range': [0, 4.5]
        },
        'width': 800,
        'height': 800,
        'shapes': [
            # unfilled circle
            {
                'type': 'circle',
                'xref': 'x',
                'yref': 'y',
                'x0': 1.0,
                'y0': 1.0,
                'x1': 1.1,
                'y1': 1.1,
                'layer': 'below',
                'line': {
                    'color': 'rgba(50, 171, 96, 1)',
                },
                'hoverinfo': 'none',
            },
        ]
    }
    return(layout)


def DrawStraightConnector(DEBUG,x0,y0,x1,y1):
    shape = [
        {
                'type': 'line',
                'xref': 'x',
                'yref': 'y',
                'x0': x0,
                'y0': y0,
                'x1': x1,
                'y1': y1,
                'line': {
                    'color': 'black',
                    'width': 2,
                },
        },

    ]
    return(shape)


def DrawElbowConnector(DEBUG,x0,y0,x1,y1,x2,y2,x3,y3):
    shape = [
        {
                'type': 'line',
                'xref': 'x',
                'yref': 'y',
                'x0': x0,
                'y0': y0,
                'x1': x1,
                'y1': y1,
                'line': {
                    'color': 'black',
                    'width': 2,
                },
        },
        {
            'type': 'line',
            'xref': 'x',
            'yref': 'y',
            'x0': x1,
            'y0': y1,
            'x1': x2,
            'y1': y2,
            'line': {
                'color': 'black',
                'width': 2,
            },
        },
        {
            'type': 'line',
            'xref': 'x',
            'yref': 'y',
            'x0': x2,
            'y0': y2,
            'x1': x3,
            'y1': y3,
            'line': {
                'color': 'black',
                'width': 2,
            },
        },

    ]
    return(shape)


def DrawRightAngleConnector(DEBUG,x0,y0,x1,y1,x2,y2):
    shape = [
        {
                'type': 'line',
                'xref': 'x',
                'yref': 'y',
                'x0': x0,
                'y0': y0,
                'x1': x1,
                'y1': y1,
                'line': {
                    'color': 'black',
                    'width': 2,
                },
        },
        {
            'type': 'line',
            'xref': 'x',
            'yref': 'y',
            'x0': x1,
            'y0': y1,
            'x1': x2,
            'y1': y2,
            'line': {
                'color': 'black',
                'width': 2,
            },
        },
    ]
    return(shape)


#The bottom left corner of the subnet will be at the x and y coordinates supplied
def PlotGatewayShape(DEBUG,x,y,textlist):
    size=0.5

    data=[]

    listsize=len(textlist)
    textinc=(size/(listsize+1))
    textx=x+(size/2)
    texty=y+textinc

    #TODO: Test with multiple gateways
    for text in textlist:
        if DEBUG:
            print("x",x)
            print("y", y)
        trace=go.Scatter(
            x=[textx],
            y=[texty],
            text=[str(text)],
            textfont=dict([('size',8)]),
            mode='text',
            textposition='middle center',
            hoverinfo='none',
        )
        data.append(trace)
        texty=texty+textinc


    shape = [
        {
            'type': 'circle',
            'xref': 'x',
            'yref': 'y',
            'x0': x,
            'y0': y,
            'x1': x+size,
            'y1': y+size,
            'layer': 'below',
            'line': {
                'color': 'rgba(50, 171, 96, 1)',
            },
            'fillcolor': 'rgba(50, 171, 96, 1)',
        }
    ]
    return(data,shape)


#The bottom left corner of the subnet will be at the x and y coordinates supplied
def PlotRouterShape(DEBUG,x,y,gwlist):
    size=0.5

    #Create a blank list that will get returned from the function
    data=[]

    #Figure out how much space we need for the text of each gateway IP
    listsize=len(gwlist)
    textinc=(size/(listsize+1))
    textx=x+(size/2)
    texty=y+textinc

    #TODO: Test with multiple gateways
    for gw in gwlist:
        if DEBUG:
            print("x",x)
            print("y", y)
        trace=go.Scatter(
            x=[textx],
            y=[texty],
            text=[str(gw)],
            textfont=dict([('size',8)]),
            mode='text',
            textposition='middle center',
            hoverinfo='none',
        )
        data.append(trace)
        texty=texty+textinc

    #Create the shape list that will be returned from the function
    shape = [
        {
            'type': 'circle',
            'xref': 'x',
            'yref': 'y',
            'x0': x,
            'y0': y,
            'x1': x+size,
            'y1': y+size,
            'layer': 'below',
            'line': {
                'color': 'rgba(4, 159, 217, 1)',
            },
            'fillcolor': 'rgba(4, 159, 217, 1)',
        }
    ]
    return(data,shape)



#The bottom left corner of the subnet will be at the x and y coordinates supplied
def PlotNessusScanner(DEBUG,x,y,text):
    size=0.4
    polygonsize=0.055
    #polygonpath="M"+str(x)+","+str(y)+" L"+str(x-polygonsize)+","+str(y+polygonsize)+" L"+str(x-polygonsize)+","+str(y+(polygonsize*2))+" L"+str(x)+","+str(y+(polygonsize*3))+" L"+str(x+polygonsize)+","+str(y+(polygonsize*3))+" L"+str(x+(polygonsize*2))+","+str(y+(polygonsize*2))+" L"+str(x+(polygonsize*2))+","+str(y+(polygonsize))+" L"+str(x+(polygonsize))+","+str(y)+" Z"
    polygonpath="M"+str(x)+","+str(y)+" L"+str(x-polygonsize*4)+","+str(y+polygonsize)+" L"+str(x-polygonsize*5)+","+str(y+(polygonsize*5))+" L"+str(x-polygonsize*2)+","+str(y+(polygonsize*8))+" L"+str(x+polygonsize*2)+","+str(y+(polygonsize*7))+" L"+str(x+(polygonsize*3))+","+str(y+(polygonsize*3))+" Z"

    data=[]

    trace = go.Scatter(
        x=[x-0.07],
        y=[y+0.05+(size/2)],
        text=["N"],
        textfont=dict([('size', 32)]),
        mode='text',
        textposition='middle center',
        hoverinfo='none',
    )
    data.append(trace)

    trace = go.Scatter(
        x=[x-0.07],
        y=[y+0.175],
        text=[text],
        textfont=dict([('size', 6)]),
        mode='text',
        textposition='bottom center',
        hoverinfo='none',

    )
    data.append(trace)


    shape = [
        {
                'type': 'path',
                'path': polygonpath,
                'layer': 'below',
                'line': {
                    'color': 'rgba(50, 171, 96, 1)',
                },
                'fillcolor': 'rgba(50, 171, 96, 1)',
      }
    ]
    return(data,shape)


#The bottom left corner of the subnet will be at the x and y coordinates supplied
def PlotNessusNetworkMonitor(DEBUG,x,y,text):
    size=0.4
    polygonsize=0.055
    polygonpath="M"+str(x)+","+str(y)+" L"+str(x-polygonsize*4)+","+str(y+polygonsize)+" L"+str(x-polygonsize*5)+","+str(y+(polygonsize*5))+" L"+str(x-polygonsize*2)+","+str(y+(polygonsize*8))+" L"+str(x+polygonsize*2)+","+str(y+(polygonsize*7))+" L"+str(x+(polygonsize*3))+","+str(y+(polygonsize*3))+" Z"

    data=[]

    trace = go.Scatter(
        x=[x-0.07],
        y=[y+0.05+(size/2)],
        text=["NNM"],
        textfont=dict([('size', 24)]),
        mode='text',
        textposition='middle center',
        hoverinfo='none',
    )
    data.append(trace)

    trace = go.Scatter(
        x=[x-0.07],
        y=[y+0.175],
        text=[text],
        textfont=dict([('size', 6)]),
        mode='text',
        textposition='bottom center',
        hoverinfo='none',

    )
    data.append(trace)


    shape = [
        {
                'type': 'path',
                'path': polygonpath,
                'layer': 'below',
                'line': {
                    'color': 'rgba(128, 128, 128, 1)',
                },
                'fillcolor': 'rgba(128, 128, 128, 1)',
      }
    ]
    return(data,shape)


def OldPlotNessusScanner(DEBUG,x,y,text):
    size=0.4

    data=[]

    trace = go.Scatter(
        x=[x+(size/2)],
        y=[y+(size/2)],
        text=["N"],
        textfont=dict([('size', 32)]),
        mode='text',
        textposition='middle center',
        hoverinfo='none',
    )
    data.append(trace)

    trace = go.Scatter(
        x=[x+(size/2)],
        y=[y+0.1],
        text=[text],
        textfont=dict([('size', 6)]),
        mode='text',
        textposition='bottom center',
        hoverinfo='none',

    )
    data.append(trace)


    shape = [
        {
                'type': 'circle',
                'xref': 'x',
                'yref': 'y',
                'x0': x,
                'y0': y,
                'x1': x+size,
                'y1': y+size,
                'layer': 'below',
                'line': {
                    'color': 'rgba(50, 171, 96, 1)',
                },
                'fillcolor': 'rgba(50, 171, 96, 1)',
      }
    ]
    return(data,shape)

#The bottom left corner of the subnet will be at the x and y coordinates supplied
def PlotSubnetShape(DEBUG,x,y,text):
    length=1.5

    trace0 = go.Scatter(
        x=[x+0.15],
        y=[y],
        text=[str(text)],
        mode='text',
        textposition='top right',
        hoverinfo = 'none',
    )

    shape =  [
            #rectangle
            {
                'type': 'rect',
                'xref': 'x',
                'yref': 'y',
                'x0': x+0.05,
                'y0': y,
                'x1': x+0.1+length,
                'y1': y+0.1,
                'layer': 'below',
                'line': {
                    'color': 'rgba(50, 171, 96, 1)',
                    'width': 3,
                },
                'fillcolor': 'rgba(50, 171, 96, 1)',
            },
            # start (left) unfilled circle
            {
                'type': 'circle',
                'xref': 'x',
                'yref': 'y',
                'x0': x,
                'y0': y,
                'x1': x+0.1,
                'y1': y+0.1,
                'layer': 'below',
                'line': {
                    'color': 'rgba(50, 171, 96, 1)',
                },
                'fillcolor': 'white',
            },
            # end curve, made by a  circle
            {
                'type': 'circle',
                'xref': 'x',
                'yref': 'y',
                'x0': x+0.05+length,
                'y0': y,
                'x1': x+0.15+length,
                'y1': y+0.1,
                'layer': 'below',
                'line': {
                    'color': 'rgba(50, 171, 96, 1)',
                },
                'fillcolor': 'rgba(50, 171, 96, 1)',
            },


    ]
    data=[trace0]
    return(data,shape)

#The bottom left corner of the subnet will be at the x and y coordinates supplied
def PlotText(DEBUG,x,y,text):

    trace0 = go.Scatter(
        x=[x],
        y=[y],
        text=[str(text)],
        mode='text',
        textposition='top right',
        hoverinfo = 'none',
    )

    data=[trace0]
    return(data)



#
#This map draws an individual subnet, all aligned along 0 on the X-axis,
# and each new subnet is an increment down the Y-axis.
# From the subnet, draw a line out and then 90 degrees down.
# From there, run a horizontal line across.  If there are any gateways,
# put them here, incrementing the X position.
# Also, if there are hosts, increment them along the X.
#
# The nodes are drawn separate from the connectors.
#
def CreateSubnetSummary(DEBUG,tenabledata,age,IGNOREEMPTYSUBNETS):
    if DEBUG:
        print("Plotting Subnet Overview")
    # build a blank graph
    G = nx.Graph()

    if len(tenabledata['subnets']) >= 20:
        graphwidth=640
        graphheight=160*len(tenabledata['subnets'])/5
        xrange=4
        yrange=len(tenabledata['subnets'])/5
    else:
        graphwidth=640
        graphheight=640
        xrange=4
        yrange=4


    #initialize various variables
    y=0.1
    x=0.1
    subnetyoffset=0.2
    summarytext="<b>Subnet Overview</b>:"
    netmaskcount={}
    data = []
    layout = {
        'xaxis': {
            'range': [0, xrange],
            'visible': False,
            'showline': False,
            'zeroline': False,
        },
        'showlegend': False,
        'yaxis': {
            'range': [0, yrange],
            'visible': False,
            'showline': False,
            'zeroline': False,
        },
        'width': graphwidth,
        'height': graphheight,
        'shapes': [],
        'title': "Subnet Overview",
        'titlefont': dict(size=16),
        'hovermode': 'closest',
        'margin': dict(b=20, l=5, r=5, t=40),
        'annotations': [dict(
            text="Generated by <a href='https://github.com/cybersmithio/networkmapper'> networkmapper.py</a>",
            showarrow=False,
            xref="paper", yref="paper",
            x=0.005, y=-0.002)],
    }

    #Go through all the subnets and put a node on the graph
    for (index,subnet) in tenabledata['subnets']:
        #Find out how many IP addresses are on the subnet:
        ipcount=0
        for i in tenabledata['ipaddresses']:
            if isinstance(i,ipaddress.IPv4Address):
                if subnet.overlaps(ipaddress.IPv4Network(str(i)+"/32")):
                    if DEBUG:
                        print("IP addresss",i,"is part of subnet",subnet,"so adding to count")
                    ipcount+=1
            elif isinstance(i,ipaddress.IPv6Address):
                if subnet.overlaps(ipaddress.IPv6Network(str(i)+"/128")):
                    if DEBUG:
                        print("IP addresss",i,"is part of subnet",subnet,"so adding to count")
                    ipcount+=1

        if IGNOREEMPTYSUBNETS == False or (IGNOREEMPTYSUBNETS==True and ipcount > 0):
            #This subnet should be drawn (it is not 0, or drawing 0 host subnets are okay)
            (text, shapeinfo) = PlotSubnetShape(DEBUG, x, y, str(subnet)+"  Total IPs: "+str(ipcount))
            for i in shapeinfo:
                layout['shapes'].append(i)
            for i in text:
                data.append(i)

            #Increment the y axis for the next subnet
            y=y+subnetyoffset

            #Pull out the subnet of this network and add it to the summary count
            (dump,netmask)=re.split(r'\/', str(subnet), maxsplit=2)
            try:
                if DEBUG:
                    print("Incrementing subnet count for /"+str(netmask))
                netmaskcount[netmask]+=1
            except:
                if DEBUG:
                    print("Initializing subnet count for /"+str(netmask))
                netmaskcount[netmask]=1

    #Create the summary text of all the subnet netmasks, and do a total for all subnets
    subnetcount=0
    for i in netmaskcount.keys():
        summarytext=summarytext+"<br>/"+str(i)+" subnets: "+str(netmaskcount[i])
        subnetcount+=netmaskcount[i]
    summarytext=summarytext+"<br><br><b>Total subnets</b>: "+str(subnetcount)

    if DEBUG:
        print("Summary text for subnet diagram",summarytext)

    layout['annotations']=[dict(
            text="Generated by <a href='https://github.com/cybersmithio/networkmapper'>networkmapper.py</a>",
            showarrow=False,
            xref="paper", yref="paper",
            x=0.005, y=-0.002),
            dict(
            text=summarytext,
            showarrow=False,
            width=200,
            height=int((y-subnetyoffset)*160),
            valign='middle',
            align='left',
            bgcolor='white',
            borderwidth=3,
            x=2,
            y=0,
            xanchor='left',
            yanchor='bottom'
            )]

    layout['yaxis'] =  {
        'range': [0, y+1],
        'visible': False,
        'showline': False,
        'zeroline': True,
    }
    layout['height']=(y+1)*160

    fig = go.Figure(data=data,
                    layout=layout)

    # Open the graph in a browser window
    plotly.offline.plot(fig, auto_open=True)


def AnalyzeFreeAddresses(DEBUG,tenabledata):
    if DEBUG:
        print("Going through hosts without a subnet, and creating classful subnets")

    freeaddresses=[]
    for address in tenabledata['ipaddresses']:
        NOSUBNET=True
        for (sni, subnet) in tenabledata['subnets']:
            if type(address) == ipaddress.IPv4Address:
                if DEBUG:
                    print("Checking if",ipaddress.ip_network(str(address)+"/32"),"is in subnet",subnet)
                if subnet.overlaps(ipaddress.ip_network(str(address)+"/32")):
                    if DEBUG:
                        print("YES, this ip belongs to this network")
                    NOSUBNET=False
            else:
                #TODO: Make test case to confirm this line works
                if subnet.overlaps(ipaddress.ip_network(str(address) + "/128")):
                    NOSUBNET = False
        if NOSUBNET == True:
            freeaddresses.append(address)

    if DEBUG:
        print("\n\n\nThese IP addresses exist but there was not enough subnet information about them to put onto diagram (total of " \
            +str(len(freeaddresses))+" out of "+str(len(tenabledata['ipaddresses']))+"):\n\n",freeaddresses)

    #Go through the addresses, convert them into their classful equivalents, and create subnets based on that.
    subnets=[]
    classa = ipaddress.IPv4Network("0.0.0.0/1")
    classb = ipaddress.IPv4Network("128.0.0.0/2")
    classc = ipaddress.IPv4Network("192.0.0.0/3")
    for address in freeaddresses:
        if isinstance(address,ipaddress.IPv4Address):
            if classa.overlaps(ipaddress.ip_network(str(address) + "/32")):
                i=ipaddress.IPv4Interface(str(address) + "/8")
                if DEBUG:
                    print("Class A address:",address,"becomes",i.network)
                tenabledata['subnets']=MergeSubnets(tenabledata['subnets'],i.network)
            elif classb.overlaps(ipaddress.ip_network(str(address) + "/32")):
                i = ipaddress.IPv4Interface(str(address) + "/16")
                if DEBUG:
                    print("Class B address:", address,"becomes",i.network)
                tenabledata['subnets'] = MergeSubnets(tenabledata['subnets'], i.network)
            elif classc.overlaps(ipaddress.ip_network(str(address) + "/32")):
                i = ipaddress.IPv4Interface(str(address) + "/24")
                if DEBUG:
                    print("Class C address:",address,"becomes",i.network)
                tenabledata['subnets'] = MergeSubnets(tenabledata['subnets'], i.network)
        else:
            if DEBUG:
                print("Nothing to be done with an IPv6 address:",address)

    print("Subnets derived from free IP addresses",subnets)

    return(tenabledata)


######################
###
### Program start
###
######################



# Get the arguments from the command line
parser = argparse.ArgumentParser(description="Pulls information from Tenable.io or Tenable.sc to create a network map. (Currently just text)")
parser.add_argument('--accesskey',help="The Tenable.io access key",nargs=1,action="store")
parser.add_argument('--secretkey',help="The Tenable.io secret key",nargs=1,action="store")
parser.add_argument('--username',help="The SecurityCenter username",nargs=1,action="store")
parser.add_argument('--password',help="The SecurityCenter password",nargs=1,action="store")
parser.add_argument('--host',help="The Tenable.io host. (Default is cloud.tenable.com)",nargs=1,action="store")
parser.add_argument('--port',help="The Tenable.io port. (Default is 443)",nargs=1,action="store")
parser.add_argument('--debug',help="Turn on debugging",action="store_true")
parser.add_argument('--testpattern',help="Draw a test pattern",action="store_true")
parser.add_argument('--outfile',help="A file to dump all the raw data into, for debugging or offline use.",nargs=1,action="store")
parser.add_argument('--offlinefile',help="A file from a previous run of the networkmapper, which can be used to generate a map offline.",nargs=1,action="store")
parser.add_argument('--exclude-public',help="Do not include public IPv4 ranges when mapping",action="store_true")
parser.add_argument('--ignore-empty-subnets',help="Do not include subnets that do not have any hosts detected",action="store_true")
parser.add_argument('--age',help="The maximum age in days of the Tenable data to use.",nargs=1,action="store")

args=parser.parse_args()

DEBUG=False
EXCLUDEPUBLIC=False
IGNOREEMPTYSUBNETS=False

if args.debug:
    DEBUG=True
    print("Debugging is enabled.")

if args.exclude_public:
    EXCLUDEPUBLIC=True
    print("Excluding public IP addresses and subnets.")

if args.ignore_empty_subnets:
    IGNOREEMPTYSUBNETS=True
    print("Ignoring empty subnets.")


if args.testpattern:
    CreateTestPattern(DEBUG)
    exit(0)

# Pull as much information from the environment variables
# as possible, and where missing then initialize the variables.
if os.getenv('TIO_ACCESS_KEY') is None:
    accesskey = ""
else:
    accesskey = os.getenv('TIO_ACCESS_KEY')

# If there is an access key specified on the command line, this override anything else.
try:
    if args.accesskey[0] != "":
        accesskey = args.accesskey[0]
except:
    nop = 0


if os.getenv('TIO_SECRET_KEY') is None:
    secretkey = ""
else:
    secretkey = os.getenv('TIO_SECRET_KEY')


# If there is an  secret key specified on the command line, this override anything else.
try:
    if args.secretkey[0] != "":
        secretkey = args.secretkey[0]
except:
    nop = 0

if os.getenv('SC_USERNAME') is None:
    username = ""
else:
    username = os.getenv('SC_USERNAME')

try:
    if args.username[0] != "":
        username = args.username[0]
        #Since a specific username was found on the command line, assume the user does not want to poll Tenable.io
        secretkey = ""
        accesskey = ""
except:
    username=""

if os.getenv('SC_PASSWORD') is None:
    username = ""
else:
    username = os.getenv('SC_PASSWORD')

try:
    if args.password[0] != "":
        password = args.password[0]
except:
    password=""

try:
    if args.port[0] != "":
        port = args.port[0]
except:
    port = "443"

try:
    if args.age[0] != "":
        age = args.age[0]
except:
    age = None



outfile = None
try:
    if args.outfile[0] != "":
        outfile = args.outfile[0]
except:
    outfile = None


offlinefile = None
try:
    if args.offlinefile[0] != "":
        offlinefile = args.offlinefile[0]
except:
    offlinefile = None


tenabledata={}
# Create the data structures for normalization
#A list of IP addresses found.  Each element is a tuple with an index and the IPv4Address or IPv6Address object representing the IP address.
tenabledata['ipaddresses'] = []
#A list of assets found.  Each element is a tuple with an index, an asset ID, and a list of  IPv4Address and IPv6Address objects.
tenabledata['assets'] = []
#A list of subnets found.  Each element is a tuple with the an index and the IPv4Network or IPv6Network object representing the subnet.
tenabledata['subnets'] = []

#A list of gateways found.  Each element is a tuple with the an index and the IPv4Address or IPv6Address object representing the gateway.
tenabledata['gateways'] = []
#A list of routes found.  Each element is a tuple with the an index, the IPv4Network or IPv6Network object
# and an IPv4Address or IPv6Address object for the gateway.
tenabledata['routes'] = []
#A list of scanners found. Each element is a tuple with an index, the type of scanner, and the IPv4Address or IPv6Address object representing the IP address.
tenabledata['scanners'] = []
#A list of routing devices.  Each element is a tuple with an index, a list of gateways (IPv4Address and IPv6Address objects),
#  and a list of subnets  (IPv4Networks and IPv6Networks objects).
# This should all be calculated from the data from Tenable.
tenabledata['routers'] = []

#A list of traceroute data.  Each element is a dict, and each dict element contains an index, the source and destination (IPv4Address or IPv6Address),
# and a list of the hops (IPv4Address or IPv6Address, or None when something didn't respond.)
tenabledata['traceroutes'] = []


if offlinefile == None:
    if accesskey != "" and secretkey != "":
        print("Connecting to cloud.tenable.com with access key", accesskey, "to report on assets")
        try:
            if args.host[0] != "":
                host = args.host[0]
        except:
            host = "cloud.tenable.com"
        conn = ConnectIO(DEBUG, accesskey, secretkey, host, port)
    elif username != "" and password != "":
        try:
            if args.host[0] != "":
                host = args.host[0]
        except:
            host = "127.0.0.1"
        print("Connecting to SecurityCenter with username " + str(username) + " @ https://" + str(host) + ":" + str(port))
        conn = ConnectSC(DEBUG, username, password, host, port)

    if conn == False:
        print("There was a problem connecting.")
        exit(-1)
    tenabledata=GatherInfo(DEBUG,outfile,conn,tenabledata,EXCLUDEPUBLIC,age)
else:
    tenabledata=ParseOfflineFile(DEBUG,offlinefile)


tenabledata=AnalyzeFreeAddresses(DEBUG,tenabledata)

tenabledata=AnalyzeRouters(DEBUG,tenabledata)

tenabledata=MatchRoutersToAssets(DEBUG,tenabledata)

CreateSubnetSummary(DEBUG, tenabledata,age,IGNOREEMPTYSUBNETS)
#CreateMapPlot(DEBUG, tenabledata,age)
CreateMapPlotRouters(DEBUG, tenabledata,age,IGNOREEMPTYSUBNETS)

exit(0)




