#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Requires sentinel-mgmt-sdk-0.9.8
# Sentinel One Auto-Importer to TheHive SIRP via Python 2.x
import json
import logging
import datetime

from management.mgmtsdk_v2.mgmt import Management
from management.mgmtsdk_v2.services.threat import ThreatQueryFilter
from thehive4py.api import TheHiveApi
from thehive4py.models import (
    Case,
    CaseObservable,
)
from thehive4py.query import ContainsString

# environmental variables
S1API = ""
S1WEB = ""
HiveAPI = ""
HiveWEB = ""
DAYS = 7


def main():
    api = TheHiveApi(HiveWEB, HiveAPI)
    S1Management = Management(hostname=S1WEB, api_token=S1API)
    filter = ThreatQueryFilter()
    tod = datetime.datetime.now()
    d = datetime.timedelta(days=DAYS)
    filter.apply("createdAt", tod - d, op="gt")
    filter.apply("resolved", False, op="eq")
    threats = S1Management.threats.get(query_filter=filter)
    i = 0
    while True:
        threat = threats.json["data"][i]
        string = searchCaseByDescription(api, threat["id"])
        if string is None:
            threat_values = createKeys(threat)
            parsed = createAlertDescription(threat_values)
            case = Case(
                title=threat["description"],
                tlp=0,
                pap=0,
                severity=1,
                flag=False,
                tags=[
                    "Sentinel One",
                    threat["classification"],
                    threat["agentOsType"],
                ],
                description=parsed,
                status="Open",
                createdAt=threat["createdDate"],
            )
            response = api.create_case(case)
            if response.status_code == 201:
                logging.info(json.dumps(response.json(), indent=4, sort_keys=True))
                id = response.json()["id"]
                postUpdate(api, id, threat)
            else:
                logging.error("ko: {}/{}".format(response.status_code, response.text))
        i += 1
        if i == len(threats.json["data"]):
            cursor = threats.pagination["nextCursor"]
            if not cursor:
                break
            threats = S1Management.threats.get(cursor=cursor)
            i = 0


def postUpdate(api, string, threat):
    file_observable = CaseObservable(
        dataType="filename",
        data=[threat["filePath"]],
        tlp=1,
        ioc=False,
        tags=["Auto Imported", "Filename", "Suspicious"],
        message="Filepath Observable from Sentinel One Alert",
    )
    response = api.create_case_observable(string, file_observable)
    return response


def searchCaseByDescription(api, string):
    # search case with a specific string in description
    # returns the ES case ID
    query = ContainsString("description", string)
    range = "all"
    response = api.find_cases(query=query, range=range)
    try:
        if response.status_code != 200:
            error = dict()
            error["message"] = "search case failed"
            error["query"] = query
            error["payload"] = response.json()
            raise ValueError(json.dumps(error, indent=4, sort_keys=True))
        if len(response.json()) == 1:
            # one case matched, set Id
            esCaseId = response.json()[0]["id"]
            return esCaseId
        elif len(response.json()) == 0:
            # no cases matched
            return None
        else:
            # unknown case value, likely multiple response
            raise ValueError("Unknown case value returned, skipping...")
    except:
        pass
    return ""


def createKeys(threat):
    parsed = {
        "agentId": threat.get("agentId", None),
        "agentIp": threat.get("agentIp", None),
        "agentIsActive": threat.get("agentIsActive", None),
        "agentNetworkStatus": threat.get("agentNetworkStatus", None),
        "Annotation": threat.get("annotation", None),
        "AnnotationURL:": threat.get("annotationUrl", None),
        "Benign:": threat.get("markedAsBenign", None),
        "CertValid:": threat.get("isCertValid", None),
        "Classifier:": threat.get("classifierName", None),
        "ComputerName:": threat.get("agentComputerName", None),
        "CreatedDate:": threat.get("createdDate", None),
        "Decommisioned:": threat.get("agentIsDecommissioned", None),
        "Description:": threat.get("description", None),
        "Domain:": threat.get("agentDomain", None),
        "DotNet:": threat.get("fileIsDotNet", None),
        "FileHash:": threat.get("fileContentHash", None),
        "FileMaliciousContent:": threat.get("fileMaliciousContent", None),
        "FileObjectID:": threat.get("fileObjectId", None),
        "FilePath:": threat.get("filePath", None),
        "From:": threat.get("fromScan", None),
        "FromCloud:": threat.get("fromCloud", None),
        "ThreatID": threat.get("id", None),
        "indicators": threat.get("indicators", None),
        "Infected:": threat.get("agentInfected", None),
        "MachineType:": threat.get("agentMachineType", None),
        "MaliciousGroupL": threat.get("maliciousGroupId", None),
        "Mitigated:": threat.get("mitigationStatus", None),
        "MitigationMode:": threat.get("mitigationMode", None),
        "OS:": threat.get("agentOsType", None),
        "Partial:": threat.get("isPartialStory", None),
        "Publisher:": threat.get("publisher", None),
        "Rank:": threat.get("rank", None),
        "S1AgentVersion:": threat.get("threatAgentVersion", None),
        "Sha256:": threat.get("fileSha256", None),
        "SiteID:": threat.get("siteId", None),
        "Source:": threat.get("classificationSource", None),
        "ThreatName:": threat.get("threatName", None),
        "UserName:": threat.get("username", None),
        "Verification:": threat.get("fileVerificationType", None),
    }
    return parsed


def createAlertDescription(threat_values):
    url = f"https://{S1WEB}/analyze/threats/{threat_values['ThreatID']}/overview"
    description = "## Summary\n\n"
    for key, value in threat_values.items():
        if value is None:
            pass
        elif value is False:
            pass
        else:
            description += "- **" + str(key) + "**  " + (str(value)) + " \n"
    description += "```\n\n" + "Sentinel One Alert Url: " + url
    return description


if __name__ == "__main__":
    main()
