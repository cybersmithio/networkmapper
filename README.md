# networkmapper

This script pulls data out of a Tenable product and generates a network map using Plotly. It works with either Tenable.io or Tenable.sc.


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


# Example running with Tenable.sc (formerly SecurityCenter).
```
python3 networkmapper.py --username ********* --password ******** --host 127.0.0.1 --port 8443
```

# Example of running in debug mode.  *very* verbose
```
python3 networkmapper.py --username ********* --password ******** --host 127.0.0.1 --port 8443 --debug
```

