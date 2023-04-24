# Query vulnerable PIP packages

This is a simple script to query GitHub's GraphQL API for vulnerable PIP packages.

```bash
$ python3 -m venv venv
$ source venv/bin/activate
(venv) $ python3 -m pip install -r requirements.txt
(venv) $ python3 query_pip_vulnerabilities.py
```
