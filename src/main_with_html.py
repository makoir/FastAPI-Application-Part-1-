import json
import requests
from fastapi import FastAPI
from datetime import datetime, timedelta

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates


with open("vuln.json", "r", encoding="utf8") as f:
    vuln_json = json.load(f)

vuln = vuln_json["vulnerabilities"]

templates = Jinja2Templates(directory="src/templates")

app = FastAPI()

# / - для того щоб вибрати ендпоінт
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("start_page.html", {"request": request})

#  /info - Має виводити інформацію про додаток, вас як автора
@app.get("/info", response_class=HTMLResponse)
def inform(request: Request):
    return templates.TemplateResponse(name="inform.html", request=request, context={
        "author": "Marko Yavorskiy",
        "about_application": "This FastAPI application pulls data from json file about CVEs and displays it to you."
    })

# /get/all - Має виводити CVE за останні 5 днів. Максимум 40 CVE
@app.get('/get/all/', response_class=HTMLResponse)
def five_days_cve(request: Request):
    current_date = datetime.now()
    f_ago_date = current_date - timedelta(days=90)
    f_days_cve = []
    try:
        for i in vuln:
            add_date = datetime.fromisoformat(i["dateAdded"])
            if add_date >= f_ago_date:
                f_days_cve.append(i)
        if f_days_cve:
            return templates.TemplateResponse(name="cve.html", request=request, context={"cves": f_days_cve[:40]})
        else:
            return "No vulnerabilities for last 5 days"
    except Exception as error:
        return error

# /get/new - Має виводити 10 найновіших CVE
@app.get("/get/new", response_class=HTMLResponse)
def ten_new_cve(request: Request):
    try:
        if vuln:
            sort_response = sorted(vuln, key=lambda x: x['dateAdded'])
            return templates.TemplateResponse(name="cve.html", request=request, context={"cves": sort_response[-10:]})
        else:
            return "No vulneabilities"
    except Exception as error:
        return error
    

# /get/critical - Має виводити 10 критичних CVE
@app.get("/get/known", response_class=HTMLResponse)
def critical_cve(request: Request):
    all_know_cve = []
    try:
        for i in vuln:
            if "Known" == i["knownRansomwareCampaignUse"]:
                all_know_cve.append(i)
        if all_know_cve:
            return templates.TemplateResponse(name="cve.html", request=request, context={"cves": all_know_cve[:10]})
        else:
            return "No critical vulneabilities"
    except Exception as error:
        return error


# #  /get?query="key" - Має виводити CVE які містять ключове слово
@app.get("/get", response_class=HTMLResponse)
def get_keyword_cve(query, request: Request):
    keyword_cve = []
    for i in vuln:
        if query in i["shortDescription"] or query in i["vulnerabilityName"] or query in i["vendorProject"] or query in i["product"] or query in i["knownRansomwareCampaignUse"]:
            keyword_cve.append(i)
    if keyword_cve:
        return templates.TemplateResponse(name="cve.html", request=request, context={"cves": keyword_cve})
    else:
        return "No vulneabilities with this keyword"

        