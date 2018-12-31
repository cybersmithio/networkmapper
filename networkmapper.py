#!/usr/bin/python
#
# Takes a Tenable.io asset data and generates a CSV report.
# The output file is called tio-asset-download.csv
#
# Example usage with environment variables:
# TIOACCESSKEY="********************"; export TIOACCESSKEY
# TIOSECRETKEY="********************"; export TIOSECRETKEY
# ./tio-asset-download.py
#
# This script requires the Tenable.io Python SDK to be installed.
# If this is not already done, then run pip install tenable_io
#

import json
import os
import sys
from tenable.io import TenableIO
from tenable.sc import TenableSC
import argparse
import re
import ipaddress

#Testing
#pip install plotly networkx
import plotly.plotly as py
import plotly
import plotly.graph_objs as go
import networkx as nx


def DownloadAssetInfoIO(DEBUG,conn,ipaddresses,assets):
    TIO=False
    if str(type(conn))  == "<class 'tenable.io.TenableIO'>":
        TIO=True

    if TIO:
        for asset in conn.assets.list():
            IPV4=False
            IPv6=False
            if DEBUG:
                print("Asset ID:",asset['id'])
                print("Asset IPv4 addresses:", asset['ipv4']) if 'ipv4' in asset else print("")
                print("Asset info:",asset)
            if 'ipv4' in asset:
                if DEBUG:
                    if len(asset['ipv4']) > 1:
                        print("This is a multi-homed asset")
                IPV4=True
                for i in asset['ipv4']:
                    ipaddresses.append(tuple([len(ipaddresses),ipaddress.IPv4Address(i)]))
            if 'ipv6' in asset:
                if DEBUG:
                    if len(asset['ipv6']) > 1:
                        print("This is a multi-homed asset")
                IPV6=True
                for i in asset['ipv6']:
                    ipaddresses.append(tuple([len(ipaddresses), ipaddress.IPv6Address(i)]))
            if IPV4 and IPV6:
                assets.append(tuple([len(assets),asset['id'],asset['ipv4']+asset['ipv6']]))
            elif IPV4 and not IPV6:
                assets.append(tuple([len(assets),asset['id'],asset['ipv4']]))
            elif IPV6 and not IPV4:
                assets.append(tuple([len(assets),asset['id'],asset['ipv6']]))
            else:
                if DEBUG:
                    print("This asset had no IP addresses.  Weird, right?!")
    else:
        try:
            assets = sc.analysis.vulns(tool="sumip")

        except:
            assets = []
            print("Error getting ip list", sys.exc_info()[0], sys.exc_info()[1])

        for asset in assets:
            if DEBUG:
                print("Asset info:", asset)
            if 'ip' in asset:
                ipaddresses.append(tuple([len(ipaddresses), ipaddress.IPv4Address(asset['ip'])]))

    if DEBUG:
        print("\n\n\n")
        print("Assets found:",assets)
        print("IP addresses found:",ipaddresses)
        print("\n\n\n")

    return(ipaddresses,assets)


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



#Takes the scanner and merges it to the existing scanner list, ensuring no duplicates between the two
#The orig should be a list of scanners (i.e. IPv4Addres types)
#the new should be an IPv4Address or IPv6Address type
def MergeScanners(orig,new):

    FOUND=False
    for i in orig:
        (index,scanner)=i
        if scanner == new:
            FOUND=True

    #If we didn't find a match, then add it to the orig
    if FOUND == False:
        orig.append(tuple([len(orig), new]))

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
def GetPlugin24272(DEBUG,conn,ipaddresses,assets,subnets,gateways,routes):
    if DEBUG:
        print("Parsing information from all plugin ID 24272")

    TIO=False
    if str(type(conn))  == "<class 'tenable.io.TenableIO'>":
        TIO=True

    try:
        if TIO:
            results=conn.workbenches.vuln_outputs(24272)
        else:
            results = conn.analysis.vulns(('pluginID', '=', '24272'), tool="vulndetails")
    except:
        results=[]
        print("Error getting output from 24272", sys.exc_info()[0], sys.exc_info()[1])


    for i in results:
        if DEBUG:
            print("Result info:",i)
        if TIO:
            (subnets,gateways,routes)=ParsePlugin24272(DEBUG,i['plugin_output'],subnets,gateways,routes)
        else:
            (subnets,gateways,routes)=ParsePlugin24272(DEBUG,i['pluginText'],subnets,gateways,routes)

    if DEBUG:
        print("Summary of information collected from all instances of Plugin 24272")
        print("Type:",type(subnets))
        print("Subnets:",subnets)
        print("Type:",type(subnets))
        print("Gateways:",gateways)
        print("Type:",type(subnets))
        print("Routes:",routes)

        return(ipaddresses, assets, subnets, gateways, routes)




#Takes the text which should be from a Plugin Output for Plugin ID 24272, and parses it.
#Merges the data with the existing subnets, gateways, and routes lists, and then returns those.
def ParsePlugin24272(DEBUG,text,subnets,gateways,routes):
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
        if (not n1.is_multicast)  and (not n1.is_loopback) and (not n1.is_reserved) and (netmask != "255.255.255.255"):
            #Only save the route and subnet info if this is not a multicast, loopback, reserved,  or host
            if DEBUG:
                print("Saving subnet:")
            if n1 != defaultroute:
                subnets = MergeSubnets(subnets, n1)
            if not gw=="0.0.0.0":
                #Only save the gateway and route if the gateway is not 0.0.0.0
                gateways = MergeGateways(DEBUG, gateways, ipaddress.IPv4Address(gw))
                routes = MergeRoutes(routes, n1,ipaddress.IPv4Address(gw))

    if DEBUG:
        print("Summary of information collected")
        print("Subnets:",subnets)
        print("Gateways:",gateways)
        print("Routes:",routes)
        print("\n\n\n")

    return(subnets,gateways,routes)


#Gathers subnet info from SecurityCenter or Tenable.io from Plugin 10663
def GetPlugin10663(DEBUG,conn,subnets,gateways,routes):
    if DEBUG:
        print("Parsing information from all plugin ID 10663")

    #Assume we're using a SecurityCenter connection unless we know the connection is for Tenable.io
    TIO=False
    if str(type(conn))  == "<class 'tenable.io.TenableIO'>":
        TIO=True

    try:
        if TIO:
            results=conn.workbenches.vuln_outputs(10663)
        else:
            results = conn.analysis.vulns(('pluginID', '=', '10663'), tool="vulndetails")
    except:
        results=[]
        print("Error getting plugin info", sys.exc_info()[0], sys.exc_info()[1])

    for i in results:
        if DEBUG:
            print("Result info:",i)
        if TIO:
            (subnets, gateways, routes) = ParsePlugin10663(DEBUG, i['plugin_output'], subnets, gateways, routes)
        else:
            (subnets,gateways,routes)=ParsePlugin10663(DEBUG,i['pluginText'],subnets,gateways,routes)

    if DEBUG:
        print("Summary of information collected from all instances of Plugin 10663")
        print("Subnets:",subnets)
        print("Gateways:",gateways)
        print("Routes:",routes)

    return(subnets,gateways,routes)


#Takes the text which should be from a Plugin Output for Plugin ID 24272, and parses it.
#Merges the data with the existing subnets, gateways, and routes lists, and then returns those.
def ParsePlugin10663(DEBUG,text,subnets,gateways,routes):
    if DEBUG:
        print("Parsing plugin text from 10663",text)
    gw=""
    for i in re.findall("Router : ([0-9\.]+)",text,flags=re.IGNORECASE+re.MULTILINE):
        if DEBUG:
            print("Router found:",i)
        gw=i
        gateways = MergeGateways(DEBUG,gateways, ipaddress.IPv4Address(gw))

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
        subnets=MergeSubnets(subnets,s1)
        if gw != "":
            routes=MergeRoutes(routes,s1,ipaddress.IPv4Address(gw))


    return(subnets,gateways,routes)


#Gathers subnet info from SecurityCenter or Tenable.io from Plugin 10287
def GetPlugin10287(DEBUG,conn,subnets,gateways,routes,scanners):
    if DEBUG:
        print("Parsing information from all plugin ID 10287")

    #Assume we're using a SecurityCenter connection unless we know the connection is for Tenable.io
    TIO=False
    if str(type(conn))  == "<class 'tenable.io.TenableIO'>":
        TIO=True

    try:
        if TIO:
            results=conn.workbenches.vuln_outputs(10287)
        else:
            results = conn.analysis.vulns(('pluginID', '=', '10287'), tool="vulndetails")
    except:
        results=[]
        print("Error getting plugin info", sys.exc_info()[0], sys.exc_info()[1])

    for i in results:
        if DEBUG:
            print("Result info:",i)
        if TIO:
            (subnets, gateways, routes,scanners) = ParsePlugin10287(DEBUG, i['plugin_output'], subnets, gateways, routes,scanners)
        else:
            (subnets,gateways,routes,scanners)=ParsePlugin10287(DEBUG,i['pluginText'],subnets,gateways,routes,scanners)

    if DEBUG:
        print("Summary of information collected from all instances of Plugin 10287")
        print("Subnets:",subnets)
        print("Gateways:",gateways)
        print("Routes:",routes)

    return(subnets,gateways,routes,scanners)


#Takes the text which should be from a Plugin Output for Plugin ID 10287, and parses it.
#Merges the data with the existing subnets, gateways, and routes lists, and then returns those.
def ParsePlugin10287(DEBUG,text,subnets,gateways,routes,scanners):
    #First, split the plugin output.
    #Assumptions:
    # First line will always be "For your information, here is the traceroute from"...
    #The last 4 lines will be the endhost blank line, the "Hop Count Line", and another blank line
    # The remaining lines will be IP addresses or possibly symbols like (?) until the "Hop Count line"
    # The first IP address will always be the scanner.
    if DEBUG:
        print("Parsing plugin text from 10287",text)

    for (scanner,endhost) in re.findall("For your information, here is the traceroute from (.*) to (.*) :",text,flags=re.IGNORECASE):
        if DEBUG:
            print("The scanner IP address is: \"" + str(scanner) + "\"")
        scanners = MergeScanners(scanners, ipaddress.IPv4Address(scanner))

    FIRSTIP=True
    lines=re.split("\n",text)
    lastaddress=len(lines)-4
    if DEBUG:
        print("Total lines found:",len(lines))
    for i in range(0,len(lines)):
        if i > 1 and i < lastaddress:
            if DEBUG:
                print("The next hop is : \""+str(lines[i])+"\"")
            try:
                gateways = MergeGateways(DEBUG, gateways, ipaddress.IPv4Address(lines[i]))
            except:
                if DEBUG:
                    print("Not a valid next hop: \"" + str(lines[i]) + "\"")

    if DEBUG:
        print("Summary of information collected")
        print("Subnets:",subnets)
        print("Gateways:",gateways)
        print("Routes:",routes)
        print("\n\n\n")

    return(subnets,gateways,routes,scanners)




def GatherInfo(DEBUG,conn,subnets,gateways,routes,ipaddresses,assets,scanners):
    (ipaddresses, assets)=DownloadAssetInfoIO(DEBUG,conn,ipaddresses,assets)

    #Gather interface enumeration
    (ipaddresses,assets,subnets,gateways,routes)=GetPlugin24272(DEBUG,conn,ipaddresses,assets,subnets,gateways,routes)

    #Gather info from DHCP
    (subnets, gateways, routes)=GetPlugin10663(DEBUG,conn,subnets,gateways,routes)

    #Gather traceroute info.
    # This should also provide the information on a Nessus scanner itself, since the first IP will be the scanner.
    (subnets, gateways, routes, scanners)=GetPlugin10287(DEBUG,conn,subnets,gateways,routes,scanners)

    # 10551 gives some clues to interfaces via SNMP.  This could potentially be used to make a routing map

    #92370 shows ARP tables, so important for matching MAC addresses to IP addresses.


    #Plugin ID 132 can sometimes provide information about other IP or MAC addresses on the system.
    # (i.e. 192.168.15.1 belongs to 192.168.16.1 because this plugin says so, and the hostname is the same)


    #Plugin ID 19 can show that there are multiple VLANs on a host, potentially indicating a gateway

    #56310 can show some network information from the iptables, but this may not indicate actual network subnets.
    #It may be more zones.


    #35716 gives important information on MAC address matches for assets.

    #TODO: Need a function that takes data such as traceroute info, and pieces together what gateways might be connected.


    if DEBUG:
        print("Summary of information collected from all plugins")
        print("Returned IP addresses:", ipaddresses)
        print("Returned assets:", ipaddresses)
        print("Subnets:",subnets)
        print("Gateways:",gateways)
        print("Scanners:",scanners)
        print("Routes:",routes)



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
def CreateMapPlot(DEBUG,subnets,gateways,routes,ipaddresses,assets):
    # build a blank graph
    G = nx.Graph()

    y=1
    x=0.1
    subnetyoffset=1

    data = []
    layout = {
        'xaxis': {
            'range': [0, 20],
            'visible': False,
            'showline': False,
            'zeroline': True,
        },
        'showlegend': False,
        'yaxis': {
            'range': [0, 20],
            'visible': False,
            'showline': False,
            'zeroline': True,
        },
        'width': 3200,
        'height': 3200,
        'shapes': []
    }

    #Go through all the subnets and put a node on the graph
    for (index,subnet) in subnets:
        (text, shapeinfo) = PlotSubnetShape(DEBUG, x+0.7, y+0.25, str(subnet))
        for i in shapeinfo:
            layout['shapes'].append(i)
        for i in text:
            data.append(i)

        #Try to attach a gateway to each subnet, so check all the gateways
        gwtext=[]
        for(index,gw) in gateways:
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
        for(index,ns) in scanners:
            #See if this gateway is in the current subnet, and if so, print the name
            if subnet.overlaps(ipaddress.ip_network(str(ns)+"/32")):
                gwtext.append(str(ns))
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

        y=y+subnetyoffset

    #Scaling does not work well with the font sizes, so removing this for now
    #layout['yaxis']['range']=[0,y+3]
    #layout['xaxis']['range']=[0,y+3]
    #layout['height']=y*100
    #layout['width']=y*100



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
            'line': {
                'color': 'rgba(50, 171, 96, .6)',
            },
            'fillcolor': 'rgba(50, 171, 96, .6)',
        }
    ]
    return(data,shape)


#The bottom left corner of the subnet will be at the x and y coordinates supplied
def PlotNessusScanner(DEBUG,x,y,text):
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
                'line': {
                    'color': 'rgba(50, 171, 96, .6)',
                },
                'fillcolor': 'rgba(50, 171, 96, .6)',
      }
    ]
    return(data,shape)

#The bottom left corner of the subnet will be at the x and y coordinates supplied
def PlotSubnetShape(DEBUG,x,y,text):
    length=1.0

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
                'line': {
                    'color': 'rgba(50, 171, 96, .6)',
                    'width': 3,
                },
                'fillcolor': 'rgba(50, 171, 96, .6)',
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
                'line': {
                    'color': 'rgba(50, 171, 96, .6)',
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
                'line': {
                    'color': 'rgba(50, 171, 96, .6)',
                },
                'fillcolor': 'rgba(50, 171, 96, .6)',
            },
    ]
    data=[trace0]
    return(data,shape)


def CreateSubnetSummary(DEBUG, subnets, gateways, routes, ipaddresses,assets):
    connectorthickness = 0.5
    connectorcolor = '#000'
    nodesize = 10
    xoffset = 0.05
    subnetyoffset= -0.1
    gatewayyoffset = -0.02
    hostyoffset = -0.04

    # build a blank graph
    G = nx.Graph()

    nodecount=0
    y=0
    subnettext=[]
    nodecolor=[]

    #Go through all the subnets and put a node on the graph
    for (index,subnet) in subnets:

        #New subnet, let's add a node.
        G.add_node(index,pos=(0,y))
        if DEBUG:
            print("New node",nodecount," is the subnet",subnet)
        subnetnode=nodecount
        subnettext+= tuple([subnet])
        nodecolor += tuple(["grey"])
        #In case there is no gateway, reconnect the hosts back to the subnet
        gatewaynode=nodecount

        #Done all the configuration needed for this node, so increment to the next
        nodecount=nodecount+1

        y=y+subnetyoffset


    pos = nx.get_node_attributes(G, 'pos')

    dmin = 1
    ncenter = 0
    for n in pos:
        x, y = pos[n]
        d = (x - 0.5) ** 2 + (y - 0.5) ** 2
        if d < dmin:
            ncenter = n
            dmin = d

    p = nx.single_source_shortest_path_length(G, ncenter)

    edge_trace = go.Scatter(
        x=[],
        y=[],
        line=dict(width=connectorthickness, color=connectorcolor),
        hoverinfo='none',
        mode='lines')

    for edge in G.edges():
        x0, y0 = G.node[edge[0]]['pos']
        x1, y1 = G.node[edge[1]]['pos']
        # print("x0=",x0)
        # print("y0=",y0)
        # print("x1=",x1)
        # print("y1=",y1)
        edge_trace['x'] += tuple([x0, x1, None])
        edge_trace['y'] += tuple([y0, y1, None])

    node_trace = go.Scatter(
        x=[],
        y=[],
        text=subnettext,
        textposition='bottom center',
        hovertext=subnettext,
        mode='markers+text',
        hoverinfo='text',
        marker=dict(
            showscale=True,
            # colorscale options
            # 'Greys' | 'YlGnBu' | 'Greens' | 'YlOrRd' | 'Bluered' | 'RdBu' |
            # 'Reds' | 'Blues' | 'Picnic' | 'Rainbow' | 'Portland' | 'Jet' |
            # 'Hot' | 'Blackbody' | 'Earth' | 'Electric' | 'Viridis' |
            colorscale='YlGnBu',
            reversescale=True,
            color=nodecolor,

            size=nodesize,
            colorbar=dict(
                thickness=15,
                title='Node Connections',
                xanchor='left',
                titleside='right'
            ),
            line=dict(width=2)))

    for node in G.nodes():
        x, y = G.node[node]['pos']
        node_trace['x'] += tuple([x])
        node_trace['y'] += tuple([y])

    for node, adjacencies in enumerate(G.adjacency()):
        # node_trace['marker']['color'] += tuple([len(adjacencies[1])])
        node_info = '# of connections: ' + str(len(adjacencies[1]))
        # node_trace['text'] += tuple([node_info])

    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        title='<br>Overview of subnets',
                        titlefont=dict(size=16),
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=20, l=5, r=5, t=40),
                        annotations=[dict(
                            text="Python code: <a href='https://plot.ly/ipython-notebooks/network-graphs/'> https://plot.ly/ipython-notebooks/network-graphs/</a>",
                            showarrow=False,
                            xref="paper", yref="paper",
                            x=0.005, y=-0.002)],
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)))

    #Open the graph in a browser window
    plotly.offline.plot(fig, auto_open=True)



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

args=parser.parse_args()

DEBUG=False

if args.debug:
    DEBUG=True
    print("Debugging is enabled.")

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

try:
    if args.username[0] != "":
        username = args.username[0]
except:
    username=""


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



#A list of subnets found.  Each element is a tuple with the an index and the IPv4Network or IPv6Network object representing the subnet.
subnets=[]

#A list of gateways found.  Each element is a tuple with the an index and the IPv4Address or IPv6Address object representing the gateway.
gateways=[]

#A list of routes found.  Each element is a tuple with the an index, the IPv4Network or IPv6Network object
# and an IPv4Address or IPv6Address object for the gateway.
routes=[]

#A list of IP addresses found.  Each element is a tuple with an index and the IPv4Address or IPv6Address object representing the IP address.
ipaddresses=[]

#A list of assets found.  Each element is a tuple with an index, an asset ID, and a list of  IPv4Address and IPv6Address objects.
assets=[]

#A list of scanners found. Each element is a tuple with an index and the IPv4Address or IPv6Address object representing the IP address.
scanners=[]

if accesskey != "" and secretkey != "":
    print("Connecting to cloud.tenable.com with access key", accesskey, "to report on assets")
    try:
        if args.host[0] != "":
            host = args.host[0]
    except:
        host = "cloud.tenable.com"
    conn=ConnectIO(DEBUG,accesskey,secretkey,host,port)
elif username != "" and password != "":
    try:
        if args.host[0] != "":
            host = args.host[0]
    except:
        host = "127.0.0.1"
    print("Connecting to SecurityCenter with username "+str(username)+" @ https://"+str(host)+":"+str(port))
    conn=ConnectSC(DEBUG, username, password, host, port)

if conn == False:
    print("There was a problem connecting.")
    exit(-1)



GatherInfo(DEBUG,conn,subnets,gateways,routes,ipaddresses,assets,scanners)
CreateSubnetSummary(DEBUG, subnets, gateways, routes, ipaddresses,assets)

CreateMapPlot(DEBUG, subnets, gateways, routes, ipaddresses,assets)
exit(0)




