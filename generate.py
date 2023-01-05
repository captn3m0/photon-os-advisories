import sys
import subprocess
import markdown
import json
import datetime
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
    return datetime.datetime.utcfromtimestamp(p)

def created_date(file):
    p = int(
        subprocess.check_output(
            ["git", "log", "--diff-filter=A", "--follow", "--format=%ct", "-1", "--", file],
            cwd=ADVISORIES_DIR,
        )
        .decode("utf-8")
        .strip()
    )
    return datetime.datetime.utcfromtimestamp(p)

def advisory_slug(os_version, advisory):
    _id = int(advisory.split("-")[2])
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


def __main__():
    for d in get_osv():
        fn = f"advisories/{d['id']}.json"
        with open(fn, "w") as f:
            print(f"writing to {fn}")
            f.write(json.dumps(d, indent=4, sort_keys=True))

if __name__ == "__main__":
    __main__()