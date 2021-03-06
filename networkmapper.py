#!/usr/bin/python
#
# This requires python 3.3 due to the use of the ipaddress library
#
# Takes data from Tenable.io or Tenable.sc and makes a network map.
# Written by: James Smith
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
# Verison 7 - Jan 17, 2019
#  * Colour code hosts based on vulnerabilities
#  * Colour code subnets based on vulnerabilities
#
# Version 6 - Jan 13, 2019
#   * Added "anonymize" flag so IP addresses will be replaced with asterisks
#   * Added capability to draw hosts onto the map,
#        provided the subnet only has a certain number of hosts or less as
#        specified by the user. (Otherwise the map could be pretty wide)
#
#
# Version 5:
#   * Improved subnet plot to show a summary count of the netmasks
#   * Host count in subnet label
#   * Use data of only a certain age
#   * Creates a file with all the information downloaded from Tenable.io.
#     This file can be used as a source of data in an offline mode, and can be
#     useful for debugging.
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
# Version 2 - Has functionality to identify when gateways/subnets sharerouters. Jan 3, 2019
# Version 1 - Initial version to gather information and make a basic plot.  Dec 31, 2018
#
# Future capabilities:
#   * Read a Nessus file instead of polling Tenable.io or Tenable.sc
#   * Show router interconnections (if they exist)
#   * A mode that outputs a visio macro file for drawing the diagram in visio
#   * A list on the subnet page we had 3 lists/tables:
#       - Non RFC-1918 addresses scanned (public IPs, or subnets of public IPs)
#       - Class B subnets (internal)
#       - Class C subnets  (internal)
#  * Summary data on each plot, such as the number of subnets, number of gateways, number of scanners, etc
#  * Query for all Nessus sensors, including scanners, network monitors, and agent managers, and plot
#  * Collect and analyst asset information in combination with plugin ID 24272 to identify, and if user requests then eliminate virtual machine addresses
#  * Carve out existing subnets from classful subnet guesses, so there is no overlap
#  * Add a flag to ignore route information from endpoints
#  * For private subnets (subnets without gateways and connected to hosts on other subnets), show the hosts and the private subnet connections
#  * Detect cloud assets and draw in a cloud section
#  * Draw hosts that have a certain tag from tenable.io or tenable.sc
#
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


def DownloadAssetInfoIO(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age: int):
    TIO=False
    if str(type(conn))  == "<class 'tenable.io.TenableIO'>":
        TIO=True

    if not isinstance(age,int):
        age=None

    if age != None:
        maximumage=datetime.today()-timedelta(days=age)
    else:
        maximumage=datetime(1970,1,1,0,0,0)


    if TIO:
        #Get all the vulnerabilities
        rawvulns=[]
        for i in conn.exports.vulns():
            if DEBUG:
                print("Info:", i)
                print("Asset id:",i['asset']['uuid'])
                print("severity ID:", i['severity_id'])
            # Break out fields with multiple values into a multi-line cell
            #tenabledata['assets'].append(tuple([len(tenabledata['assets']), asset['id'], ipaddresses]))
            rawvulns.append(tuple([i['asset']['uuid'], i['severity_id']]))



        #Go through each asset downloaded from Tenable.io, parse the data and store it.
        for asset in conn.assets.list():
            #Info, low, medium, high, critical
            vulncount=[0,0,0,0,0]
            for (vulnassetid,severity) in rawvulns:
                if asset['id']==vulnassetid:
                    vulncount[severity]+=1
            tenabledata['assetvulnsum'].append(tuple([asset['id'],vulncount[4], vulncount[3], vulncount[2], vulncount[1]]))

            if DEBUG:
                print("Asset ID:",asset['id'])
                print("Vulns low/medium/high/critical:",vulncount[4], vulncount[3], vulncount[2], vulncount[1])

            IPV4=False
            IPv6=False
            #We need to build a list of addresses so we can filter out things like link-local addresses
            ipaddresses=[]
            if DEBUG:
                print("Asset ID:",asset['id'])
                print("Asset IPv4 addresses:", asset['ipv4']) if 'ipv4' in asset else print("")
                print("Asset IPv6 addresses:", asset['ipv6']) if 'ipv6' in asset else print("")
                print("Asset last_seen:", asset['last_seen']) if 'last_seen' in asset else print("")
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
                                tenabledata['ipvulnsum'].append(tuple([ip, vulncount[4], vulncount[3], vulncount[2], vulncount[1]]))
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
                                tenabledata['ipvulnsum'].append(tuple([ip, vulncount[4], vulncount[3], vulncount[2], vulncount[1]]))
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
                if age < 1000:
                    assets = conn.analysis.vulns(('lastSeen','=','00:'+str(age)),tool="sumip")
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
            criticalvulns=None
            highvulns=None
            mediumvulns=None
            lowvulns=None
            if 'severityCritical' in asset:
                criticalvulns = asset['severityCritical']
            if 'severityHigh' in asset:
                highvulns = asset['severityHigh']
            if 'severityMedium' in asset:
                mediumvulns = asset['severityMedium']
            if 'severityLow' in asset:
                lowvulns = asset['severityLow']
            tenabledata['ipvulnsum'].append(tuple([ipaddress.IPv4Address(asset['ip']), criticalvulns, highvulns, mediumvulns, lowvulns]))

        if DEBUG:
            print("Total assets retrieved from tenable.sc:",assetcount)


    if DEBUG:
        print("\n\n\n")
        print("Assets found:",tenabledata['assets'])
        print("IP addresses found:",tenabledata['ipaddresses'])
        print("Tenable asset vulnerability summary:",tenabledata['assetvulnsum'])
        print("Tenable ip vulnerability summary:",tenabledata['ipvulnsum'])
        print("\n\n\n")

    return(tenabledata)


def DownloadScanners(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age: int):
    TIO=False
    if str(type(conn))  == "<class 'tenable.io.TenableIO'>":
        TIO=True

    if not isinstance(age,int):
        age=None


    if age != None:
        maximumage=datetime.today()-timedelta(days=age)
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
# the new should be an IPv4Network type
#If the new subnet is a supernet of an existing subnet,
# then the new subnet is broken up into smaller components
def MergeSubnets(DEBUG,orig,new):
    if DEBUG:
        print("MergeSubnets: Merging",new,"into existing subnets")

    new=[new]

    RESTART=True
    while RESTART:
        RESTART=False
        for i in orig:
            for j in new:
                if i == j:
                    if DEBUG:
                        print("MergeSubnets: New subnet already exists, so nothing needs to be done")
                    new.remove(j)
                elif j.supernet_of(i):
                    if DEBUG:
                        print("MergeSubnets: The new subnet",j," is a supernet of existing subnet",i,". Breaking up new subnet",j)
                    #One of the new subnets overlaps with an existing subnet
                    #Remove the existing subnet from the new subnets list
                    new.remove(j)
                    new += list(j.address_exclude(i))
                    if DEBUG:
                        print("MergeSubnets: New subnets are now:",new)
                elif i.supernet_of(j):
                    if DEBUG:
                        print("MergeSubnets: An existing subnet",i," is a supernet of new subnet",j,". Breaking up existing subnet",i)
                        print("Current subnets:", orig)
                    #One of the new subnets overlaps with an existing subnet
                    #Remove the existing subnet from the new subnets list
                    orig.remove(i)
                    orig += list(i.address_exclude(j))
                    if DEBUG:
                        print("MergeSubnets: Rewrote",i,"as",list(i.address_exclude(j)))
                    # The original subnet was modified, so we need to break out of the iterator for the original subnet and restart
                    if DEBUG:
                        print("MergeSubnets: Breaking out of loop")
                    RESTART=True
                    break
            if RESTART:
                if DEBUG:
                    print("MergeSubnets: Breaking out of loop")
                #The original subnet was modified, so we need to break out of the iterator for the original subnet and restart
                break


    #Whatever new subnets are remaining, add that:
    if len(new) > 0:
        for i in new:
            orig.append(i)
            if DEBUG:
                print("MergeSubnets: Appending subnet", i)

    return(orig)


# Takes the subnets and merges them, ensuring no duplicates between the two
# The orig should be a list of subnets (i.e. IPv4Network types)
# the new should be an IPv4Network type
def OldMergeSubnets(orig, new):
    FOUND = False

    for i in orig:
        (index, subnet) = i
        if subnet == new:
            FOUND = True

    # If we didn't find a match, then add it to the orig
    if FOUND == False:
        orig.append(tuple([len(orig), new]))

    return (orig)

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
def GetPlugin24272(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age: int):
    if DEBUG:
        print("Parsing information from all plugin ID 24272")

    if not isinstance(age,int):
        age=None

    TIO=False
    if str(type(conn))  == "<class 'tenable.io.TenableIO'>":
        TIO=True

    try:
        if TIO:
            results=conn.workbenches.vuln_outputs(24272,age=age)
        else:
            if age == None:
                results = conn.analysis.vulns(('pluginID', '=', '24272'), tool="vulndetails")
            else:
                results = conn.analysis.vulns(('pluginID', '=', '24272'),('lastSeen', '=', '00:' + str(age)), tool="vulndetails")
    except:
        results=[]
        print("Error getting output from 24272", sys.exc_info()[0], sys.exc_info()[1])


    #First parse for interface information, which has the most accurate netmask data for the subnets.
    for i in results:
        if DEBUG:
            print("Result info:",i)
        if TIO:
            tenabledata=ParsePlugin24272ForInterfaceInfo(DEBUG,i['plugin_output'],tenabledata,EXCLUDEPUBLIC)
        else:
            tenabledata=ParsePlugin24272ForInterfaceInfo(DEBUG,i['pluginText'],tenabledata,EXCLUDEPUBLIC)

    if DEBUG:
        print("Summary of information collected from  Plugin 24272 from just the interface information\n")
        for i in tenabledata:
            print(i)
            print(tenabledata[i],"\n")


    #Then parse routing information, which can have more aggregated data for subnets.
    for i in results:
        if DEBUG:
            print("Result info:",i)
        if TIO:
            tenabledata=ParsePlugin24272ForRoutingInfo(DEBUG,i['plugin_output'],tenabledata,EXCLUDEPUBLIC)
        else:
            tenabledata=ParsePlugin24272ForRoutingInfo(DEBUG,i['pluginText'],tenabledata,EXCLUDEPUBLIC)



    if DEBUG:
        print("Summary of information collected from  Plugin 24272\n")
        for i in tenabledata:
            print(i)
            print(tenabledata[i],"\n")

    return(tenabledata)




#Takes the text which should be from a Plugin Output for Plugin ID 24272, and parses it.
#Merges the data with the existing subnets, gateways, and routes lists, and then returns those.
#Make sure we do not include anything from 169.254.0.0/16
def ParsePlugin24272ForInterfaceInfo(DEBUG,text,tenabledata,EXCLUDEPUBLIC):
    if DEBUG:
        print("Parsing plugin text from 24272 for interface information",text)
    for i in re.findall("IPAddress/IPSubnet = ([0-9\.]*\/[0-9\.]*)",text,flags=re.IGNORECASE+re.MULTILINE):
        if DEBUG:
            print("Subnet found:",i)
        #This is reliable information on the subnet and netmask, so add it
        tenabledata['subnets'] = MergeSubnets(DEBUG,tenabledata['subnets'], ipaddress.IPv4Interface(i).network)


    if DEBUG:
        print("Summary of information collected after parsing output from 24272 For Interface Info")
        print("Subnets:",tenabledata['subnets'])
        print("Gateways:",tenabledata['gateways'])
        print("Routes:",tenabledata['routes'])
        print("\n\n\n")

    return(tenabledata)


#Takes the text which should be from a Plugin Output for Plugin ID 24272, and parses it.
#Merges the data with the existing subnets, gateways, and routes lists, and then returns those.
#Make sure we do not include anything from 169.254.0.0/16
def ParsePlugin24272ForRoutingInfo(DEBUG,text,tenabledata,EXCLUDEPUBLIC):
    if DEBUG:
        print("Parsing plugin text from 24272 for routing information",text)

    pattern=re.compile("Routing Information")

    try:
        (ifaceinfo,routeinfo)=pattern.split(text,maxsplit=2)
    except:
        routeinfo=""
    if DEBUG:
        print("Route info section:",routeinfo)

    #This information may be more aggregated and less useful.
    #TODO: We need to check the subnet information obtained and if it is less specific then don't use it.
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
                    tenabledata['subnets'] = MergeSubnets(DEBUG,tenabledata['subnets'], n1)
            if not gw=="0.0.0.0":
                #Only save the gateway and route if the gateway is not 0.0.0.0
                tenabledata['gateways'] = MergeGateways(DEBUG, tenabledata['gateways'], ipaddress.IPv4Address(gw))
                tenabledata['routes'] = MergeRoutes(tenabledata['routes'], n1,ipaddress.IPv4Address(gw))

    if DEBUG:
        print("Summary of information collected after parsing output from 24272 for routing information")
        print("Subnets:",tenabledata['subnets'])
        print("Gateways:",tenabledata['gateways'])
        print("Routes:",tenabledata['routes'])
        print("\n\n\n")

    return(tenabledata)



#Gathers subnet info from SecurityCenter or Tenable.io from Plugin 10663
def GetPlugin10663(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age: int):
    if DEBUG:
        print("Parsing information from all plugin ID 10663")

    if not isinstance(age,int):
        age=None


    #Assume we're using a SecurityCenter connection unless we know the connection is for Tenable.io
    TIO=False
    if str(type(conn))  == "<class 'tenable.io.TenableIO'>":
        TIO=True

    try:
        if TIO:
            results=conn.workbenches.vuln_outputs(10663,age=age)
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
#Plugin 10663 is regarding DHCP information
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
            tenabledata['subnets']=MergeSubnets(DEBUG,tenabledata['subnets'],s1)
        if gw != "":
            tenabledata['routes']=MergeRoutes(tenabledata['routes'],s1,ipaddress.IPv4Address(gw))


    return(tenabledata)


#Gathers subnet info from SecurityCenter or Tenable.io from Plugin 10287
def GetPlugin10287(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age: int):
    if DEBUG:
        print("Parsing information from all plugin ID 10287")

    if not isinstance(age,int):
        age=None


    #Assume we're using a SecurityCenter connection unless we know the connection is for Tenable.io
    TIO=False
    if str(type(conn))  == "<class 'tenable.io.TenableIO'>":
        TIO=True

    try:
        if TIO:
            results=conn.workbenches.vuln_outputs(10287,age=age)
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
def GetPlugin12(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age: int):
    if DEBUG:
        print("Parsing information from all plugin ID 12")

    if not isinstance(age,int):
        age=None

    #Assume we're using a SecurityCenter connection unless we know the connection is for Tenable.io
    TIO=False
    if str(type(conn))  == "<class 'tenable.io.TenableIO'>":
        TIO=True

    try:
        if TIO:
            results=conn.workbenches.vuln_outputs(12,age=age)
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



def AnalyzeSubnets(DEBUG,tenabledata):

    #Go through all the subnets and put a node on the graph
    for subnet in tenabledata['subnets']:
        #Critical, high, medium, and low vulnerabilities for this subnet
        vulnsum = [0, 0, 0, 0]

        for (ip,crit,high,med,low) in tenabledata['ipvulnsum']:
            if isinstance(ip,ipaddress.IPv4Address):
                if subnet.overlaps(ipaddress.IPv4Network(str(ip)+"/32")):
                    if DEBUG:
                        print("IP addresss",ip,"is part of subnet",subnet,"so adding to count")
                    vulnsum[0]+=crit
                    vulnsum[1]+=high
                    vulnsum[2]+=med
                    vulnsum[3]+=low
            elif isinstance(ip,ipaddress.IPv6Address):
                if subnet.overlaps(ipaddress.IPv6Network(str(ip)+"/128")):
                    if DEBUG:
                        print("IP addresss",ip,"is part of subnet",subnet,"so adding to count")
                    vulnsum[0]+=crit
                    vulnsum[1]+=high
                    vulnsum[2]+=med
                    vulnsum[3]+=low
        if DEBUG:
            print("Vulnerability summary for subnet",subnet," is (crit/high/med/low)",vulnsum[0],vulnsum[1],vulnsum[2],vulnsum[3])
        tenabledata['subnetvulnsum'].append(tuple([subnet,vulnsum[0],vulnsum[1],vulnsum[2],vulnsum[3]]))

    return(tenabledata)


#subnet should be an IPv4Network or IPv6Network object
def CalculateVulnsInSubnetByAsset(DEBUG,subnet,tenabledata):
    ipcount=0
    for i in tenabledata['assets']:
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
        for subnet in tenabledata['subnets']:

            if subnet.overlaps(ipaddress.ip_network(str(gwaddr) + "/32")):
                gwsubnetlist.append(tuple([gwaddr,subnet]))
                SNFOUND=True
        if SNFOUND==False:
            if DEBUG:
                print("There was no subnet found for the gateway",gwaddr)
            gwsubnetlist.append(tuple([gwaddr, None]))

    #Now go through all the subnets and to catch all the subnets that might not have gateways discovered.
    for subnet in tenabledata['subnets']:
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
                        if DEBUG:
                            print("Matched the scanner",scanner,"with the subnet",i)
                        entry1 = i
            # Find a match with the endhost
            for i in gwsubnetlist:
                (gw, subnet) = i
                # We only care if the entry has both a gateway and subnet, otherwise we cannot do anything with it for now.
                if gw != None and subnet != None:
                    if subnet.overlaps(ipaddress.ip_network(str(endhost) + "/32")):
                        if DEBUG:
                            print("Matched the endhost",endhost,"with the subnet",i)
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
        try:
            x.append(ipaddress.IPv4Network(i))
        except:
            x.append(ipaddress.IPv6Network(i))
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

    x = []
    for i in tenabledata['vulnsum']:
        (a,b,c,d,e) = i
        try:
            x.append(tuple([a,b,c,d,e]))
        except:
            print("Error reading vulnerability summary")
    tenabledata['vulnsum']=x


    outfp=open("test.txt","w")
    DumpPluginsToFile(DEBUG,outfp,tenabledata)
    outfp.close

    return(tenabledata)

def GatherInfo(DEBUG,outputfile,conn,tenabledata,EXCLUDEPUBLIC,age: int):
    print("Starting information gathering.")

    if not isinstance(age,int):
        age=None


    tenabledata=DownloadAssetInfoIO(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age)

    #tenabledata=DownloadScanners(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age)

    #Gather info from DHCP first.  This has detailed information about
    # network masks, with less change of aggregation like the routing table from 24272
    tenabledata=GetPlugin10663(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age)

    #Gather information on NNM detections
    tenabledata=GetPlugin12(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age)

    #Gather traceroute info.
    # This should also provide the information on a Nessus scanner itself, since the first IP will be the scanner.
    tenabledata=GetPlugin10287(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age)


    #Gather interface enumeration
    tenabledata=GetPlugin24272(DEBUG,conn,tenabledata,EXCLUDEPUBLIC,age)






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




def CreateMapPlotRouters(DEBUG,tenabledata,age: int,IGNOREEMPTYSUBNETS, drawmaxhosts,ANONYMIZE,subnetcoloroptions,hostcoloroptions):
    if DEBUG:
        print("Starting to create the network diagram with routers")
        print("Subnet color options",subnetcoloroptions)
        print("Host color options",hostcoloroptions)

    # build a blank graph
    G = nx.Graph()
    y=1
    x=0.1
    subnetyoffset=0.7

    if not isinstance(age,int):
        age=None


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
            'visible': True,
            'showline': True,
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
        if DEBUG:
            print("Attempting to draw router with these IP addresses",gwlist)
        subnetcount=0

        #Plot each subnet that will be attached to this router
        subnetx=x
        subnety=y
        for subnet in snlist:
            if DEBUG:
                print("First, plotting this subnet",subnet)
            #Set a flag if this subnet has an NNM
            NNM=False

            hostsinsubnet=CalculateHostsInSubnet(DEBUG,subnet,tenabledata)
            if IGNOREEMPTYSUBNETS == False or (IGNOREEMPTYSUBNETS == True and hostsinsubnet > 0):
                if DEBUG:
                    print("Confirmed subnet should be drawn.")
                subnetcount+=1
                #Draw the subnet
                if ANONYMIZE:
                    subnettext="*.*.*.*"
                else:
                    subnettext=str(subnet)

                if subnetcoloroptions=="highestseverity":
                    if DEBUG:
                        print("Coloring subnet by highest severity")
                    for (i,crit,high,med,low) in tenabledata['subnetvulnsum']:
                        if i == subnet:
                            if crit > 0:
                                subnetcolor="red"
                            elif high > 0:
                                subnetcolor = "orange"
                            elif med > 0:
                                subnetcolor="rgba(213,201,32,1)"
                            elif low > 0:
                                subnetcolor='rgba(50, 171, 96, 1)'
                            else:
                                subnetcolor = 'rgba(4, 159, 217, 1)'
                            (text, shapeinfo) = PlotSubnetShape(DEBUG, subnetx + 1, subnety + 0.25, str(subnettext) + "   IP addresses:" + str(hostsinsubnet), subnetcolor)
                elif subnetcoloroptions=="severityspectrum":
                    if DEBUG:
                        print("Coloring subnet by severity spectrum")
                    for (i,crit,high,med,low) in tenabledata['subnetvulnsum']:
                        if i == subnet:
                            (text, shapeinfo) = PlotSubnetShapeVulnSpectrum(DEBUG, subnetx + 1, subnety + 0.25, str(subnettext) + "   IP addresses:" + str(hostsinsubnet), crit, high, med,low)
                else:
                    if DEBUG:
                        print("Regular subnet coloring")
                    (text, shapeinfo) = PlotSubnetShape(DEBUG, subnetx + 1, subnety + 0.25, str(subnettext)+"   IP addresses:"+str(hostsinsubnet),'rgba(50, 171, 96, 1)')
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
                    SENSORMATCH=False
                    if sensortype == "scanner":
                        #See if this gateway is in the current subnet, and if so, print the name
                        if isinstance(ns,ipaddress.IPv4Address):
                            if subnet.overlaps(ipaddress.ip_network(str(ns)+"/32")):
                                SENSORMATCH=True
                        if isinstance(ns, ipaddress.IPv6Address):
                            if subnet.overlaps(ipaddress.ip_network(str(ns) + "/128")):
                                SENSORMATCH=True
                        if SENSORMATCH:
                            if maxxusage < subnetx+3.1+(scannercount*0.7):
                                maxxusage=subnetx+3.1+(scannercount*0.7)
                            if ANONYMIZE:
                                scannertext = "*.*.*.*"
                            else:
                                scannertext = str(ns)
                            (text, shapeinfo) = PlotNessusScanner(DEBUG, subnetx+3.1+(scannercount*0.7), subnety-0.2, scannertext)
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
                        SENSORMATCH = False
                        if DEBUG:
                            print("Checking if network monitor needs to be draw")
                        if isinstance(ns,ipaddress.IPv4Address):
                            if subnet.overlaps(ipaddress.ip_network(str(ns) + "/32")):
                                SENSORMATCH=True
                        if isinstance(ns, ipaddress.IPv6Address):
                            if subnet.overlaps(ipaddress.ip_network(str(ns)+"/128")):
                                SENSORMATCH = True
                        if SENSORMATCH:
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

                if DEBUG:
                    print("Maximum X usage after drawing sensors:",subnetx+2.1+(scannercount*0.7)+.1)
                hostx=subnetx+3.0+(scannercount*0.7)
                #Check if hosts should be drawn and if the number of hosts on this subnet is equal to or under the limit
                if drawmaxhosts >= hostsinsubnet:
                    if DEBUG:
                        print("Drawing hosts for this subnet.")
                        print("First trying to utilize asset data")
                    for (assetindex,assetid,ipaddresses) in tenabledata['assets']:
                        DRAWASSET=False
                        #Check if any of the IP addresses on this asset belong to this subnet

                        for i in ipaddresses:
                            if isinstance(i,ipaddress.IPv4Address):
                                if subnet.overlaps(ipaddress.ip_network(str(i) + "/32")):
                                    DRAWASSET=True
                            if isinstance(i, ipaddress.IPv6Address):
                                if subnet.overlaps(ipaddress.ip_network(str(i) + "/128")):
                                    DRAWASSET = True
                        if DRAWASSET:
                            if DEBUG:
                                print("Drawing asset with IP address",i,"at x position",hostx)
                            if ANONYMIZE:
                                ipaddresses = list(["*.*.*.*"])

                            if hostcoloroptions == "highestseverity":
                                if DEBUG:
                                    print("Drawing host",i,"using high severity for color")
                                for (ip, crit, high, med, low) in tenabledata['ipvulnsum']:
                                    if i == ip:
                                        if crit > 0:
                                            hostcolor = "red"
                                        elif high > 0:
                                            hostcolor = "orange"
                                        elif med > 0:
                                            hostcolor = "rgba(213,201,32,1)"
                                        elif low > 0:
                                            hostcolor = 'rgba(50, 171, 96, 1)'
                                        else:
                                            hostcolor = 'rgba(4, 159, 217, 1)'
                                        (text, shapeinfo) = PlotHostShape(DEBUG, hostx - 0.2, subnety - 0.2, ipaddresses, hostcolor)
                            elif hostcoloroptions=="severityspectrum":
                                if DEBUG:
                                    print("Drawing host using severity spectrum for color")
                                for (ip, crit, high, med, low) in tenabledata['ipvulnsum']:
                                    if i == ip:
                                        (text, shapeinfo) = PlotHostShapeBySpectrum(DEBUG, hostx - 0.2, subnety - 0.2, ipaddresses, crit, high, med,low)
                            else:
                                if DEBUG:
                                    print("Drawing host using regular gray coloring")
                                (text, shapeinfo) = PlotHostShape(DEBUG, hostx - 0.2, subnety - 0.2, ipaddresses, 'rgba(192, 192, 192, 1)')


                            for i in shapeinfo:
                                layout['shapes'].append(i)
                            for i in text:
                                data.append(i)
                            (shapeinfo) = DrawRightAngleConnector(DEBUG, subnetx + 2.65, subnety + 0.3, hostx, subnety + 0.3, hostx, subnety + 0.22)
                            for i in shapeinfo:
                                layout['shapes'].append(i)
                            hostx=hostx+0.5
                if maxxusage < hostx+0.5:
                    maxxusage=hostx+0.5

                subnety+=subnetyoffset
        #See if there were any subnets for this router.
        if subnetcount > 0:
            #Plot the router and merge into the plot data
            if ANONYMIZE:
                gwlist = list(["*.*.*.*"])

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
def CreateMapPlot(DEBUG,tenabledata,age: int):
    # build a blank graph
    G = nx.Graph()


    if not isinstance(age,int):
        age=None

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
    for subnet in tenabledata['subnets']:
        (text, shapeinfo) = PlotSubnetShape(DEBUG, x+0.7, y+0.25, str(subnet),'rgba(50, 171, 96, 1)')
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

    (text,shapeinfo)=PlotSubnetShape(DEBUG,2,2,"xxx.xxx.xxx.xxx/xx",'rgba(50, 171, 96, 1)')
    for i in shapeinfo:
        layout['shapes'].append(i)
    for i in text:
        data.append(i)

    (text,shapeinfo)=PlotSubnetShapeVulnSpectrum(DEBUG,2,2.2,"xxx.xxx.xxx.xxx/xx",3,10,5,6)
    for i in shapeinfo:
        layout['shapes'].append(i)
    for i in text:
        data.append(i)

    (text,shapeinfo)=PlotSubnetShapeVulnSpectrum(DEBUG,2,2.4,"xxx.xxx.xxx.xxx/xx",0,10,5,6)
    for i in shapeinfo:
        layout['shapes'].append(i)
    for i in text:
        data.append(i)

    (text,shapeinfo)=PlotSubnetShapeVulnSpectrum(DEBUG,2,2.6,"xxx.xxx.xxx.xxx/xx",0,10,5,0)
    for i in shapeinfo:
        layout['shapes'].append(i)
    for i in text:
        data.append(i)

    (text,shapeinfo)=PlotSubnetShapeVulnSpectrum(DEBUG,2,2.8,"xxx.xxx.xxx.xxx/xx",3,0,5,0)
    for i in shapeinfo:
        layout['shapes'].append(i)
    for i in text:
        data.append(i)

    (text,shapeinfo)=PlotSubnetShapeVulnSpectrum(DEBUG,2,3.0,"xxx.xxx.xxx.xxx/xx",0,0,0,0)
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


    (text,shapeinfo)=PlotHostShape(DEBUG,1,2,["xxx.xxx.xxx.xxx","xxx.xxx.xxx.xxx"],'rgba(192, 192, 192, 1)')
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
def PlotHostShape(DEBUG,x,y,textlist,hostcolor):
    if DEBUG:
        print("Plotting host shape for",textlist)
    size=0.4

    #Create a blank list that will get returned from the function
    data=[]

    listsize=len(textlist)
    textinc=(size/(listsize+1))
    textx=x+(size/2)
    texty=y+textinc

    for text in textlist:
        if DEBUG:
            print("x",x)
            print("y", y)
        trace=go.Scatter(
            x=[textx],
            y=[texty],
            text=str(text),
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
            'type': 'rect',
            'xref': 'x',
            'yref': 'y',
            'x0': x,
            'y0': y,
            'x1': x+size,
            'y1': y+size,
            'layer': 'below',
            'line': {
                'color': hostcolor,
            },
            'fillcolor': hostcolor,
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
def PlotSubnetShape(DEBUG,x,y,text,color: str):
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
                    'color': color,
                    'width': 3,
                },
                'fillcolor': color,
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
                    'color': color,
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
                    'color': color,
                },
                'fillcolor': color,
            },


    ]
    data=[trace0]
    return(data,shape)

def PlotHostShapeBySpectrum(DEBUG,x,y,textlist, criticals: int, highs: int, mediums: int, lows: int):
    size=0.4

    #Create a blank list that will get returned from the function
    data=[]

    startcolor="red"
    endcolor="green"
    starty=y

    #Define the y value for the vulnerabilities
    totalvulns=criticals+highs+mediums+lows
    if totalvulns > 0:
        criticalend=starty+size
        highend=starty+size*((lows+mediums+highs)/totalvulns)
        mediumend=starty+size*((lows+mediums)/totalvulns)
        lowend=starty+size*(lows)/totalvulns
        criticalstart=highend
        highstart=mediumend
        mediumstart=lowend
        lowstart=starty
    else:
        return(PlotHostShape(DEBUG,x,y,textlist,'rgba(192, 192, 192, 1)'))

    if DEBUG:
        print("Total vulns:",totalvulns)
        print("Crits/Highs/Meds/Lows:",criticals,highs,mediums,lows)
        print("Crits from ",criticalstart,"to",criticalend)
        print("Highs from ",highstart,"to",highend)
        print("Mediums from ",mediumstart,"to",mediumend)
        print("Lows from ",lowstart,"to",lowend)


    listsize=len(textlist)
    textinc=(size/(listsize+1))
    textx=x+(size/2)
    texty=y+textinc

    for text in textlist:
        if DEBUG:
            print("x",x)
            print("y", y)
        trace=go.Scatter(
            x=[textx],
            y=[texty],
            text=str(text),
            textfont=dict([('size',8)]),
            mode='text',
            textposition='middle center',
            hoverinfo='none',
        )
        data.append(trace)
        texty=texty+textinc

    #Create the shape list that will be returned from the function
    shape = []

    if criticals > 0:
        shape.append(
        {
            'type': 'rect',
            'xref': 'x',
            'yref': 'y',
            'x0': x,
            'y0': criticalstart,
            'x1': x+size,
            'y1': criticalend,
            'layer': 'below',
            'line': {
                'color': 'red',
            },
            'fillcolor': 'red',
        })
    if highs > 0:
        shape.append(
        {
            'type': 'rect',
            'xref': 'x',
            'yref': 'y',
            'x0': x,
            'y0': highstart,
            'x1': x + size,
            'y1': highend,
            'layer': 'below',
            'line': {
                'color': 'orange',
            },
            'fillcolor': 'orange',
        })
    if mediums > 0:
        shape.append(
        {
            'type': 'rect',
            'xref': 'x',
            'yref': 'y',
            'x0': x,
            'y0': mediumstart,
            'x1': x + size,
            'y1': mediumend,
            'layer': 'below',
            'line': {
                'color': 'rgba(213,201,32,1)',
            },
            'fillcolor': 'rgba(213,201,32,1)',
        })
    if lows > 0:
        shape.append(
        {
            'type': 'rect',
            'xref': 'x',
            'yref': 'y',
            'x0': x,
            'y0': lowstart,
            'x1': x + size,
            'y1': lowend,
            'layer': 'below',
            'line': {
                'color': 'rgba(50, 171, 96, 1)',
            },
            'fillcolor': 'rgba(50, 171, 96, 1)',
        })

    return(data,shape)


#The bottom left corner of the subnet will be at the x and y coordinates supplied
def PlotSubnetShapeVulnSpectrum(DEBUG,x,y,text,criticals: int, highs: int, mediums: int, lows: int):
    length=1.5

    trace0 = go.Scatter(
        x=[x+0.15],
        y=[y],
        text=[str(text)],
        mode='text',
        textposition='top right',
        hoverinfo = 'none',
    )

    startcolor="red"
    endcolor="green"
    startx=x+0.05


    #Define the x value for the vulnerabilities
    totalvulns=criticals+highs+mediums+lows
    if totalvulns > 0:
        criticalend=startx+(length+0.05)*(criticals/totalvulns)
        highend=startx+(length+0.05)*((criticals+highs)/totalvulns)
        mediumend=startx+(length+0.05)*((criticals+highs+mediums)/totalvulns)
        lowend=startx+(length+0.05)
        criticalstart=startx
        highstart=criticalend
        mediumstart=highend
        lowstart=mediumend
    else:
        return(PlotSubnetShape(DEBUG,x,y,text,'rgba(4, 159, 217, 1)'))

    #Figure out the first color
    if criticals > 0:
        startcolor = "red"
        criticalstart=startx
    elif highs > 0:
        startcolor = "orange"
        highstart=startx
    elif mediums > 0:
        startcolor = "rgba(213,201,32,1)"
        mediumstart=startx
    elif lows > 0:
        startcolor = 'rgba(50, 171, 96, 1)'
        lowstart=startx
    else:
        startcolor='rgba(4, 159, 217, 1)'

    if lows > 0:
        endcolor = 'rgba(50, 171, 96, 1)'
    elif mediums > 0:
        endcolor = "rgba(213,201,32,1)"
    elif highs > 0:
        endcolor = "orange"
    elif criticals > 0:
        endcolor = "red"
    else:
        endcolor='rgba(4, 159, 217, 1)'

    if DEBUG:
        print("Total vulns:",totalvulns)
        print("Crits/Highs/Meds/Lows:",criticals,highs,mediums,lows)
        print("Crits from ",startx,"to",criticalend)
        print("Highs from ",startx,"to",highend)
        print("Mediums from ",startx,"to",mediumend)
        print("Lows from ",startx,"to",lowend)



    shape =  [
        #critical rectangle
        {
            'type': 'rect',
            'xref': 'x',
            'yref': 'y',
            'x0': criticalstart,
            'y0': y,
            'x1': criticalend,
            'y1': y+0.1,
            'layer': 'below',
            'line': {
                'color': 'red',
                'width': 3,
            },
            'fillcolor': 'red',
        },
        # high rectangle
        {
            'type': 'rect',
            'xref': 'x',
            'yref': 'y',
            'x0': highstart,
            'y0': y,
            'x1': highend,
            'y1': y + 0.1,
            'layer': 'below',
            'line': {
                'color': 'orange',
                'width': 3,
            },
            'fillcolor': 'orange',
        },
        # medium rectangle
        {
            'type': 'rect',
            'xref': 'x',
            'yref': 'y',
            'x0': mediumstart,
            'y0': y,
            'x1': mediumend,
            'y1': y + 0.1,
            'layer': 'below',
            'line': {
                'color': 'rgba(213,201,32,1)',
                'width': 3,
            },
            'fillcolor': 'rgba(213,201,32,1)',
        },

        # low rectangle
        {
            'type': 'rect',
            'xref': 'x',
            'yref': 'y',
            'x0': lowstart,
            'y0': y,
            'x1': lowend,
            'y1': y + 0.1,
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
                'color': startcolor,
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
                'color': endcolor,
            },
            'fillcolor': endcolor,
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
def CreateSubnetSummary(DEBUG,tenabledata,age: int,IGNOREEMPTYSUBNETS,ANONYMIZE):
    if DEBUG:
        print("Plotting Subnet Overview")

    if not isinstance(age,int):
        age=None


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
    for subnet in tenabledata['subnets']:
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
            if ANONYMIZE:
                subnettext = "*.*.*.*"
            else:
                subnettext = str(subnet)

            (text, shapeinfo) = PlotSubnetShape(DEBUG, x, y, subnettext+"  Total IPs: "+str(ipcount),'rgba(50, 171, 96, 1)')
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

    #Determine all the addresses for which we do not have subnets
    freeaddresses=[]
    for address in tenabledata['ipaddresses']:
        NOSUBNET=True
        for subnet in tenabledata['subnets']:
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

    if len(freeaddresses) == 0:
        if DEBUG:
            print("No hosts without an associated subnet, so skipping this function.")
        return(tenabledata)

    #Go through the addresses, convert them into their classful equivalents, and create subnets based on that.
    subnets=[]
    freeasubnets=[]
    freebsubnets=[]
    freecsubnets=[]
    classa = ipaddress.IPv4Network("0.0.0.0/1")
    classb = ipaddress.IPv4Network("128.0.0.0/2")
    classc = ipaddress.IPv4Network("192.0.0.0/3")

    #define free address space by removing existing subnets
    if DEBUG:
        print("Defining free address space")
    for i in range(1,126):
        potentialsubnet=ipaddress.IPv4Network(str(i)+".0.0.0/8")
        freeasubnets.append(potentialsubnet)
    for i in range(128,191):
        for j in range(0,255):
            potentialsubnet=ipaddress.IPv4Network(str(i)+"."+str(j)+".0.0/16")
            freebsubnets.append(potentialsubnet)
    for i in range(192,223):
        for j in range(0,255):
            for k in range(0, 255):
                potentialsubnet=ipaddress.IPv4Network(str(i)+"."+str(j)+"."+str(k)+".0/24")
                freecsubnets.append(potentialsubnet)

    #TODO: Go through each existing subnet and remove it from the free subnet space
    if DEBUG:
        print("Removing existing subnets from free address space")
    for subnet in tenabledata['subnets']:
        if DEBUG:
            print("Removing",subnet,"from the list of open subnets")
        if classa.overlaps(subnet):
            for j in freeasubnets:
                if j.overlaps(subnet):
                    if DEBUG:
                        print("Breaking up subnet",j)
                    if not j.subnet_of(subnet):
                        if DEBUG:
                            print("Remaining subnets:",list(j.address_exclude(subnet)))
                        freeasubnets += list(j.address_exclude(subnet))
                    if DEBUG:
                        print("Removing", j, "from the list of open subnets")
                    freeasubnets.remove(j)
        elif classb.overlaps(subnet):
            for j in freebsubnets:
                if j.overlaps(subnet):
                    if DEBUG:
                        print("Breaking up subnet",j)
                    if not j.subnet_of(subnet):
                        if DEBUG:
                            print("Remaining subnets:",list(j.address_exclude(subnet)))
                        freebsubnets += list(j.address_exclude(subnet))
                    if DEBUG:
                        print("Removing", j, "from the list of open subnets")
                    freebsubnets.remove(j)
        elif classc.overlaps(subnet):
            for j in freecsubnets:
                if j.overlaps(subnet):
                    if DEBUG:
                        print("Breaking up subnet",j)
                    if not j.subnet_of(subnet):
                        if DEBUG:
                            print("Remaining subnets:",list(j.address_exclude(subnet)))
                        freecsubnets+=list(j.address_exclude(subnet))
                    if DEBUG:
                        print("Removing", j, "from the list of open subnets")
                    freecsubnets.remove(j)

    if DEBUG:
        print("Assigning free addresses to remaining free subnets.")

    for address in freeaddresses:
        if isinstance(address, ipaddress.IPv4Address):
            addresswithmask = ipaddress.ip_network(str(address) + "/32")
            if classa.overlaps(addresswithmask):
                for i in freeasubnets:
                    if i.overlaps(addresswithmask):
                        if DEBUG:
                            print("The host", address, "belongs to the network", i)
                            tenabledata['subnets'] = MergeSubnets(DEBUG,tenabledata['subnets'], i)
            elif classb.overlaps(addresswithmask):
                for i in freebsubnets:
                    if i.overlaps(addresswithmask):
                        if DEBUG:
                            print("The host", address, "belongs to the network", i)
                            tenabledata['subnets'] = MergeSubnets(DEBUG,tenabledata['subnets'], i)
            elif classc.overlaps(addresswithmask):
                for i in freecsubnets:
                    if i.overlaps(addresswithmask):
                        if DEBUG:
                            print("The host", address, "belongs to the network", i)
                            tenabledata['subnets'] = MergeSubnets(DEBUG,tenabledata['subnets'], i)
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
parser.add_argument('--test-pattern',help="Draw a test pattern",action="store_true")
parser.add_argument('--outfile',help="A file to dump all the raw data into, for debugging or offline use.",nargs=1,action="store")
parser.add_argument('--offlinefile',help="A file from a previous run of the networkmapper, which can be used to generate a map offline.",nargs=1,action="store")
parser.add_argument('--exclude-public',help="Do not include public IPv4 ranges when mapping",action="store_true")
parser.add_argument('--ignore-empty-subnets',help="Do not include subnets that do not have any hosts detected",action="store_true")
parser.add_argument('--age',help="The maximum age in days of the Tenable data to use.",nargs=1,action="store")
parser.add_argument('--draw-hosts',help="The maximum number of hosts that can exist on a subnet in order to draw the hosts.",nargs=1,action="store")
parser.add_argument('--anonymize',help="Put asterisks where IP addresses would be displayed",action="store_true")
parser.add_argument('--color-subnets-by-severity',help="Color each subnet by the highest severity that exists on it.",action="store_true")
parser.add_argument('--color-subnets-by-spectrum',help="Color each subnet by the spectrum of vulnerability severities that exists on it.",action="store_true")
parser.add_argument('--color-hosts-by-severity',help="Color each host by the highest severity that exists on it.",action="store_true")
parser.add_argument('--color-hosts-by-spectrum',help="Color each host by the spectrum of vulnerability severities that exists on it.",action="store_true")

args=parser.parse_args()

DEBUG=False
EXCLUDEPUBLIC=False
IGNOREEMPTYSUBNETS=False
ANONYMIZE=False


if args.debug:
    DEBUG=True
    print("Debugging is enabled.")

if args.exclude_public:
    EXCLUDEPUBLIC=True
    print("Excluding public IP addresses and subnets.")

if args.ignore_empty_subnets:
    IGNOREEMPTYSUBNETS=True
    print("Ignoring empty subnets.")

if args.anonymize:
    ANONYMIZE=True
    print("Anonymizing the diagrams.")

subnetcoloroptions=None
if args.color_subnets_by_severity:
    subnetcoloroptions="highestseverity"
    print("Coloring subnets by the highest severity")

if args.color_subnets_by_spectrum:
    subnetcoloroptions="severityspectrum"
    print("Coloring subnets by the severity spectrum")


hostcoloroptions=None
if args.color_hosts_by_severity:
    hostcoloroptions="highestseverity"
    print("Coloring hosts by the highest severity")

if args.color_hosts_by_spectrum:
    hostcoloroptions="severityspectrum"
    print("Coloring hosts by the severity spectrum")




if args.test_pattern:
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

username=""
#Look for a Tenable.io username
if os.getenv('SC_USERNAME') is None:
    username = ""
else:
    username = os.getenv('SC_USERNAME')
    if DEBUG:
        print("Detected SC username")
try:
    if args.username[0] != "":
        username = args.username[0]
        if DEBUG:
            print("Detected SC username")
        #Since a specific username was found on the command line, assume the user does not want to poll Tenable.io
        secretkey = ""
        accesskey = ""
except:
    username=""

#Look for a SecurityCenter password
scpassword=""
if os.getenv('SC_PASSWORD') is None:
    scpassword = ""
else:
    scpassword = os.getenv('SC_PASSWORD')
    if DEBUG:
        print("Detected SC password")
try:
    if args.password[0] != "":
        if DEBUG:
            print("Detected SC password")
        scpassword = args.password[0]
except:
    scpassword=""

#Look for a SecurityCenter port
port="443"
try:
    if args.port[0] != "":
        port = args.port[0]
except:
    port = "443"


age=None
try:
    if args.age[0] != "":
        age = int(args.age[0])
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

drawmaxhosts = 0
try:
    if args.draw_hosts[0] != "":
        try:
            drawmaxhosts = int(args.draw_hosts[0])
        except:
            print("The --draw-hosts argument must be a number")
            os._exit(-1)
except:
    drawmaxhosts = 0



tenabledata={}
# Create the data structures for normalization
#A list of IP addresses found.  Each element is a tuple with an index and the IPv4Address or IPv6Address object representing the IP address.
tenabledata['ipaddresses'] = []
#A list of assets found.  Each element is a tuple with an index, an asset ID, and a list of  IPv4Address and IPv6Address objects.
tenabledata['assets'] = []

#A list of tuples.  Each element is asset ID (if Tenable.io), and a list of critical, high, medium, and low vulns
tenabledata['assetvulnsum']=[]

#A list of tuples.  Each element is ipaddress (IPv4Address) (if Tenable.sc), and a list of critical, high, medium, and low vulns
tenabledata['ipvulnsum']=[]

#A list of tuples.  Each element is subnet (IPv4Network or IPv6Network), and a list of critical, high, medium, and low vulns
tenabledata['subnetvulnsum']=[]


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


conn=False
if offlinefile == None:
    if accesskey != "" and secretkey != "":
        print("Connecting to cloud.tenable.com with access key", accesskey, "to report on assets")
        try:
            if args.host[0] != "":
                host = args.host[0]
        except:
            host = "cloud.tenable.com"
        conn = ConnectIO(DEBUG, accesskey, secretkey, host, port)
    elif username != "" and scpassword != "":
        if DEBUG:
            print("Attempting to open connection to SC")
        try:
            if args.host[0] != "":
                host = args.host[0]
        except:
            host = "127.0.0.1"
        print("Connecting to SecurityCenter with username " + str(username) + " @ https://" + str(host) + ":" + str(port))
        conn = ConnectSC(DEBUG, username, scpassword, host, port)

    if conn == False:
        print("There was a problem connecting.")
        exit(-1)
    print("Gathering data")
    tenabledata=GatherInfo(DEBUG,outfile,conn,tenabledata,EXCLUDEPUBLIC,str(age))
else:
    print("Loading data")
    tenabledata=ParseOfflineFile(DEBUG,offlinefile)

print("Analyzing hosts without clearly defined subnet")
tenabledata=AnalyzeFreeAddresses(DEBUG,tenabledata)

print("Summarizing subnet vulnerability counts")
tenabledata=AnalyzeSubnets(DEBUG,tenabledata)


print("Analyzing network layouts")
tenabledata=AnalyzeRouters(DEBUG,tenabledata)

tenabledata=MatchRoutersToAssets(DEBUG,tenabledata)

print("Creating subnet summary diagram")
CreateSubnetSummary(DEBUG, tenabledata,age,IGNOREEMPTYSUBNETS,ANONYMIZE)
#CreateMapPlot(DEBUG, tenabledata,age)
print("Creating network diagram")
CreateMapPlotRouters(DEBUG, tenabledata,age,IGNOREEMPTYSUBNETS,drawmaxhosts,ANONYMIZE,subnetcoloroptions,hostcoloroptions)

exit(0)




