#!/usr/bin/python3

import json
import requests
import sys
import time
import yaml

def err(*args):
    print(*args, file=sys.stderr)

# Load all pipelines with this sha
sha = sys.argv[1]
if len(sys.argv) > 2:
    ignore_pipelines = int(sys.argv[2])

err("Ignoring pipelines over ", ignore_pipelines)

def load_request(what, url):
    timeout = 5
    while True:
        resp = requests.get(url)
        if resp.status_code == 200:
            return resp

        if resp.status_code == 429:
            print(f"Too many requests for {what}, waiting {timeout} sec")
            time.sleep(timeout)
            timeout *= 1.5
            continue

        raise Exception(f"Failed to load {what} ({resp.status_code}): {resp.content}")

def load_pipelines(sha):
    pipelines = []
    pageno = 1
    while True:
        resp = load_request(f"pipelines page {pageno}", f"https://gitlab.nic.cz/api/v4/projects/labs%2Fbird/pipelines?per_page=20&page={pageno}&sha={sha}")
        pipelines += (new := json.loads(resp.content))
        if len(new) == 0:
            return pipelines

        lastcount = len(pipelines)
        pageno += 1

def load_jobs(pid):
    resp = load_request(f"jobs", f"https://gitlab.nic.cz/api/v4/projects/labs%2Fbird/pipelines/{pid}/jobs?per_page=20&page=1")
    jobs = json.loads(resp.content)
    err(f"Loaded {len(jobs)} jobs")
    assert(len(jobs) < 20)
    return jobs

wait = True
while wait:

    ok = []
    wait = False

    for p in (pipelines := load_pipelines(sha)):
        if p["id"] >= ignore_pipelines:
            err(f"Ignoring pipeline {p['id']}")
            continue
        if p["status"] == "success":
            err(f"Pipeline {p['id']} already succeeded: {p['web_url']}")
            ok.append(p['id'])
        elif p["status"] == "pending" or p["status"] == "created":
            err(f"Pipeline {p['id']} pending: {p['web_url']}")
            wait = True
        elif p["status"] == "running" or p["status"] == "failed":
            err(f"Pipeline {p['id']} is {p['status']}: {p['web_url']}")
            jobs = load_jobs(p['id'])
            for j in jobs:
                if j['name'] == 'prepare':
                    if j['status'] == 'success':
                        ok.append(p['id'])
                    elif j['status'] == 'failed':
                        err("Failed in preparation")
                    else:
                        wait = True

        else:
            err(f"Pipeline {p['id']} has an unknown state {p['status']}: {p['web_url']}")

#    err(yaml.dump(pipelines))

    if len(ok) > 0:
        err(f"Found completed pipelines, no need to run again")
        for p in ok:
            print(yaml.dump({
                f"dummy-{p}": {
                    "script": [ "true" ],
                    "needs": {
                        "pipeline": str(p),
                        "job": "child-run",
                        "artifacts": False,
                        }
                    }
                }))
        exit(1)

    if wait:
        time.sleep(1)
