import sys
from glob import glob
import subprocess
import markdown
import json
import canonicaljson
import urllib.request
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


def get_osv(cve_data_all_versions):
    for os_version in PHOTON_VERSIONS:
        filename = FILE_FORMAT.format(version=os_version)
        file = ADVISORIES_DIR + filename
        print(f"Parsing {filename}")

        # Returns the version that fixed any of the given CVEs + OS + Package combination
        # there should only be one
        def cve_fixed_version(package, cves, os_version, advisory):
            # list of fixed versions with a matching
            # CVE/pkg/OS combination
            fixed_versions = set(
                [
                    x["res_ver"]
                    for cve in cves
                    for x in cve_data_all_versions.get(cve, list())
                    if (x and x["os"] == os_version and x["pkg"] == package)
                ]
            )
            # There should only be a single such reference
            if len(fixed_versions) != 1:
                f = ", ".join(list(fixed_versions))
                print(f"[{advisory}] Invalid Versions: {package} ({f})")
                return None
            return fixed_versions.pop()

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
                slug = advisory_slug(os_version, advisory)
                advisory_file = f"Security-Update-{slug}.md"
                modified = last_modified_date(advisory_file)
                published = created_date(advisory_file)

                def affected(pkg, cves, os_version):
                    r = {
                        "package": {
                            "ecosystem": f"photon:{os_version}.0",
                            "name": pkg,
                            "purl": f"pkg:rpm/vmware/{pkg}?distro=photon-{os_version}",
                        }
                    }
                    fixed_version = cve_fixed_version(pkg, cves, os_version, advisory)
                    if fixed_version:
                        r["ranges"] = {
                            "events": [
                                {"introduced": "0"},
                                {"fixed": fixed_version},
                            ],
                            "type": "ECOSYSTEM",
                        }
                    return r

                yield {
                    "id": advisory,
                    "modified": modified.isoformat("T") + "Z",
                    "published": published.isoformat("T") + "Z",
                    "related": cves,
                    "affected": [affected(pkg, cves, os_version) for pkg in packages],
                    "references": [
                        {"type": "ADVISORY", "url": ADVISORY_URL.format(slug=slug)}
                    ],
                }


def merge_advisories(advisory_file, data):

    def dedup_dicts(items):
        dedupped = [ json.loads(i) for i in set(canonicaljson.encode_canonical_json(item) for item in items)]
        return dedupped
    # read the current advisory data as json
    with open(advisory_file, "r") as f:
        original = json.load(f)
        current = copy.deepcopy(original)
    # merge the data
    assert current["id"] == data["id"]
    # Add any new data, but use a set, to avoid
    # duplicate entries
    for key in ['affected', 'references', 'related']:
        if current[key]:
            current[key].extend(data[key])
            current[key] = dedup_dicts(current[key])
        elif data[key]:
            current[key] = data[key]

    # Pick the earlier published date
    # and the later modified date
    current["published"] = (
        min(
            datetime.strptime(current["published"], "%Y-%m-%dT%H:%M:%SZ"),
            datetime.strptime(data["published"], "%Y-%m-%dT%H:%M:%SZ"),
        ).isoformat("T")
        + "Z"
    )

    current["modified"] = (
        max(
            datetime.strptime(current["modified"], "%Y-%m-%dT%H:%M:%SZ"),
            datetime.strptime(data["modified"], "%Y-%m-%dT%H:%M:%SZ"),
        ).isoformat("T")
        + "Z"
    )

    no_important_changes = True
    # One of the important keys has changed
    for key in ["affected", "references", "related", "published"]:
        if canonicaljson.encode_canonical_json(
            original[key]
        ) != canonicaljson.encode_canonical_json(current[key]):
            print(f"Found changes in {current['id']} / {key}")
            no_important_changes = False
            break

    if no_important_changes:
        return None

    return current

def fetch_cve_metadata(PHOTON_VERSIONS):
    cve_metadata = {}
    for branch in PHOTON_VERSIONS:
        url = f"https://packages.vmware.com/photon/photon_cve_metadata/cve_data_photon{branch}.0.json"
        with urllib.request.urlopen(url) as r:
            data = json.loads(r.read().decode())
            for row in data:
                row["os"] = branch
                cve = row.pop("cve_id")
                if (
                    row["aff_ver"]
                    == f"all versions before {row['res_ver']} are vulnerable"
                ):
                    del row["aff_ver"]
                else:
                    print(row)
                    raise Exception("Unimplemented affected version range")
                if cve in cve_metadata:
                    cve_metadata[cve].append(row)
                else:
                    cve_metadata[cve] = [row]
            print(f"[+] CVE metadata for Photon OS {branch}.0: Added {len(data)} CVEs")
    return cve_metadata


def __main__(advisory_id = None):
    cve_metadata = fetch_cve_metadata(PHOTON_VERSIONS)

    for d in get_osv(cve_metadata):
        # If we are only running for a single advisory
        # Check and continue if it doesn't match
        if advisory_id and d['id'] != advisory_id:
            continue
        fn = f"advisories/{d['id']}.json"
        if os.path.exists(fn):
            d = merge_advisories(fn, d)
        if d:
            with open(fn, "wb") as f:
                f.write(canonicaljson.encode_pretty_printed_json(d))


if __name__ == "__main__":
    if len(sys.argv) >=2:
        __main__(sys.argv[1])
    else:
        __main__()
