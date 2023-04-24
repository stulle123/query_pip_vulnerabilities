# Query vulnerable PIP packages

This is a simple script to query GitHub's GraphQL API for vulnerable PIP packages.

First, add your Github Access Token to the `query_pip_vulnerabilities.py` script. Then, just run the script:

```bash
$ python3 -m venv venv
$ source venv/bin/activate
(venv) $ python3 -m pip install -r requirements.txt
(venv) $ python3 query_pip_vulnerabilities.py
```
