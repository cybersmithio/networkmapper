# networkmapper

This script pulls data out of a Tenable product and generates a network map using Plotly. It works with either Tenable.io or Tenable.sc.


This is using pyTenable, so be sure you have that installed: https://pytenable.readthedocs.io/en/stable/index.html



# Example running with Tenable.io using environment variables to store the API key.
```
TIO_ACCESS_KEY="**************"; export TIO_ACCESS_KEY
TIO_SECRET_KEY="**************"; export TIO_SECRET_KEY
python3 networkmapper.py
```


# Example running with Tenable.io using environment variables on the CLI.  (Not recommended for security reasons)
```
python3 networkmapper.py --accesskey ********* --secretkey *********
```

# Example running with Tenable.io and saving the results
```
python3 networkmapper.py --outputfile output.json
```

# Example running with Tenable.io and saving the results
```
python3 networkmapper.py --offlinefile output.json
```

# Example running with Tenable.io and excluding hosts and subnets with public IP addresses
```
python3 networkmapper.py --excludepublic
```

# Example running with Tenable.sc (formerly SecurityCenter).
```
python3 networkmapper.py --username ********* --password ******** --host 127.0.0.1 --port 8443
```

# Example of running in debug mode.  *very* verbose
```
python3 networkmapper.py --username ********* --password ******** --host 127.0.0.1 --port 8443 --debug
```


# Getting better maps

Plugins 24272, 10663, and 10287 are important sources of subnet information.
Make sure to do authenticated or agent based scans to get this plugin information whenever possible.

Scan all systems frequently to use the most up-to-date information.