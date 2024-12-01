import json
import requests
from fastapi import FastAPI
from datetime import datetime, timedelta

with open("vuln.json", "r", encoding="utf8") as f:
    vulnerabilities = json.load(f)

vuln = vulnerabilities["vulnerabilities"]

app = FastAPI()

#  /info - Має виводити інформацію про додаток, вас як автора
@app.get("/info")
def inform():
    return {
        "author": "Marko Yavorskiy",
        "about application": "This FastAPI application pulls data from NIST about CVEs and displays it to you."
    }

# /get/all - Має виводити CVE за останні 5 днів. Максимум 40 CVE
@app.get('/get/all/')
def five_days_cve():
    current_date = datetime.now()
    f_ago_date = current_date - timedelta(days=5)
    f_days_cve = []
    try:
        for i in vuln:
            add_date = datetime.fromisoformat(i["dateAdded"])
            if add_date >= f_ago_date:
                f_days_cve.append(i)
        if f_days_cve:
            return f_days_cve[:40]
        else:
            return "No vulnerabilities for last 5 days"
    except Exception as error:
        print(error)

# /get/new - Має виводити 10 найновіших CVE
@app.get("/get/new")
def ten_new_cve():
    try:
        if vuln:
            return vuln[:10]
        else:
            return "No vulneabilities"
    except Exception as error:
        return error
   
# /get/critical - Має виводити 10 критичних CVE
@app.get("/get/known")
def critical_cve():
    all_know_cve = []
    try:
        for i in vuln:
            if "Known" == i["knownRansomwareCampaignUse"]:
                all_know_cve.append(i)
        if all_know_cve:
            return all_know_cve[:10]
        else:
            return "No critical vulneabilities"
    except Exception as error:
        return error

# #  /get?query="key" - Має виводити CVE які містять ключове слово
@app.get("/get")
def get_keyword_cve(query):
    keyword_cve = []
    for i in vuln:
        if query in i["shortDescription"] or query in i["vulnerabilityName"] or query in i["vendorProject"] or query in i["product"] or query in i["knownRansomwareCampaignUse"]:
            keyword_cve.append(i)
    if keyword_cve:
        return keyword_cve
    else:
        return "No vulneabilities with this keyword"
