import sys
from glob import glob
import subprocess
import markdown
import json
from datetime import datetime
import copy
import os
import re
from bs4 import BeautifulSoup

CVE_REGEX = r"CVE-\d{4}-\d{4,7}"
FILE_FORMAT = "/Security-Updates-{version}.md"
ADVISORY_URL = "https://github.com/vmware/photon/wiki/Security-Update-{slug}"
PHOTON_VERSIONS = range(1, 5)
ADVISORIES_DIR = "photon-wiki"

def last_modified_date(file):
    p = int(
        subprocess.check_output(
            ["git", "log", "--date=iso-strict", "-1", "--format=%ct", "--", file],
            cwd=ADVISORIES_DIR,
        )
        .decode("utf-8")
        .strip()
    )
    return datetime.utcfromtimestamp(p)

def created_date(file):
    with open(ADVISORIES_DIR + "/" + file) as f:
        for line in f:
            if line.startswith("Issue"):
                return datetime.strptime(line.split(": ")[1].strip(), "%Y-%m-%d")

def advisory_slug(os_version, advisory):
    _id = int(float(advisory.split("-")[2]))
    return f"{os_version}.0-{_id}"

def get_osv():
    mapping = {}
    for version in PHOTON_VERSIONS:
        filename = FILE_FORMAT.format(version=version)
        file = ADVISORIES_DIR + filename
        with open(file, "r") as f:
            table_html = markdown.markdown(
                f.read(), extensions=["markdown.extensions.tables"]
            )
            soup = BeautifulSoup(table_html, "html.parser")
            for tr in soup.find("tbody").find_all("tr"):
                (advisory, severity, published_date, packages, cves) = [
                    x.text for x in tr.find_all("td")
                ]
                packages = json.loads(packages.replace("'", '"'))
                cves = re.findall(CVE_REGEX, cves)
                slug = advisory_slug(version, advisory)
                advisory_file = f"Security-Update-{slug}.md"
                modified = last_modified_date(advisory_file)
                published = created_date(advisory_file)

                yield {
                    "id": advisory,
                    "modified": modified.isoformat("T") + "Z",
                    "published": published.isoformat("T") + "Z",
                    "related": cves,
                    "affected": [{
                        "package": {
                            "ecosystem": f"photon:{version}.0",
                            "name": p,
                            "purl": f"pkg:rpm/vmware/{p}?distro=photon-{version}"

                        }
                    } for p in packages],
                    "references": [
                        {
                            "type": "ADVISORY",
                            "url": ADVISORY_URL.format(slug=slug)
                        }

                    ]
                }

def merge_advisories(advisory_file, data):
    # read the current advisory data as json
    with open(advisory_file, "r") as f:
        original = json.load(f)
        current = copy.deepcopy(original)
    # merge the data
    assert(current['id'] == data['id'])
    current['affected'].extend(data['affected'])
    current['references'].extend(data['references'])
    current['related'].extend(data['related'])

    # Make sure no CVE references are duplicated
    current['related'] = list(set(current['related'])).sort()
    
    # Pick the earlier published date
    # and the later modified date
    current['published'] = min(
            datetime.strptime(current['published'], '%Y-%m-%dT%H:%M:%SZ'),
            datetime.strptime(data['published'], '%Y-%m-%dT%H:%M:%SZ')        
        ).isoformat("T") + "Z"

    current['modified'] = max(
            datetime.strptime(current['modified'], '%Y-%m-%dT%H:%M:%SZ'),
            datetime.strptime(data['modified'], '%Y-%m-%dT%H:%M:%SZ')        
        ).isoformat("T") + "Z"

    no_important_changes = True
    # One of the important keys has changed
    for key in ['id', 'affected', 'references', 'related', 'published']:
        if current[key] != original[key]:
            no_important_changes = False

    if no_important_changes:
        return None

    return current

def __main__():
    for advisory in glob('advisories/*.json'):
        os.remove(advisory)
    for d in get_osv():
        fn = f"advisories/{d['id']}.json"
        if os.path.exists(fn):
            print(f"Updating {fn}")
            d = merge_advisories(fn, d)
        else:
            print(f"Creating {fn}")
        if d:
            with open(fn, "w") as f:
                f.write(json.dumps(d, indent=4, sort_keys=True))

if __name__ == "__main__":
    __main__()