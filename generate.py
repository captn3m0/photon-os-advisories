import sys
from glob import glob
import subprocess
import markdown
import json
import canonicaljson
import urllib.request
import urllib.error
import datetime as DT
from datetime import datetime
import copy
import os
import re
from bs4 import BeautifulSoup

CVE_REGEX = r"CVE-\d{4}-\d{4,7}"
INDEX_HEADING = r"^# Photon OS {version}\.0\S* Security Advisories"
PHOTON_VERSIONS = range(1, 6)
ADVISORIES_DIR = "photon-wiki"
HEADERS = {"User-Agent": "Mozilla/5.0 Gecko/20100101 Firefox/126.0"}


def format_as_rfc3339(timestamp):
    return timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")


def last_modified_date(file):
    p = int(
        subprocess.check_output(
            ["git", "log", "--date=iso-strict", "-1", "--format=%ct", "--", file],
            cwd=ADVISORIES_DIR,
        )
        .decode("utf-8")
        .strip()
    )
    return datetime.fromtimestamp(p, DT.timezone.utc)


def created_date(file):
    with open(ADVISORIES_DIR + "/" + file) as f:
        for line in f:
            if line.startswith("Issue"):
                return datetime.strptime(line.split(": ")[1].strip(), "%Y-%m-%d")


def index_files(os_version):
    heading = re.compile(INDEX_HEADING.format(version=os_version), re.MULTILINE)
    for file in sorted(glob(f"{ADVISORIES_DIR}/Security-Updates-{os_version}*.md")):
        with open(file) as f:
            if heading.search(f.read()):
                yield file


def get_osv(cve_data_all_versions):
    for os_version, file in ((v, f) for v in PHOTON_VERSIONS for f in index_files(v)):
        print(f"Parsing {file}")

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
            if not soup.find("tbody"):
                continue
            for tr in soup.find("tbody").find_all("tr"):
                tds = tr.find_all("td")
                (advisory, severity, published_date, packages, cves) = [
                    x.text for x in tds
                ]
                packages = json.loads(packages.replace("'", '"'))
                cves = re.findall(CVE_REGEX, cves)
                advisory_url = tds[0].find("a")["href"]
                advisory_file = advisory_url.split("/")[-1] + ".md"
                modified = last_modified_date(advisory_file)
                published = created_date(advisory_file)

                def affected(pkg, cves, os_version):
                    r = {
                        "package": {
                            "ecosystem": f"Photon OS:{os_version}.0",
                            "name": pkg,
                            "purl": f"pkg:rpm/vmware/{pkg}?distro=photon-{os_version}",
                        }
                    }
                    fixed_version = cve_fixed_version(pkg, cves, os_version, advisory)
                    if fixed_version:
                        r["ranges"] = [
                            {
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": fixed_version},
                                ],
                                "type": "ECOSYSTEM",
                            }
                        ]
                    return r

                yield {
                    "id": advisory,
                    "modified": format_as_rfc3339(modified),
                    "published": format_as_rfc3339(published),
                    "related": cves,
                    "affected": [affected(pkg, cves, os_version) for pkg in packages],
                    "references": [{"type": "ADVISORY", "url": advisory_url}],
                }


def merge_advisories(advisory_file, data):

    def dedup_dicts(items):
        dedupped = [
            json.loads(i)
            for i in set(canonicaljson.encode_canonical_json(item) for item in items)
        ]
        return dedupped

    # read the current advisory data as json
    with open(advisory_file, "r") as f:
        original = json.load(f)
        current = copy.deepcopy(original)
    # merge the data
    assert current["id"] == data["id"]

    # Add any new data, but use a set, to avoid
    # duplicate entries
    for key in ["affected", "related", "references"]:
        if current[key]:
            current[key].extend(data[key])
            current[key] = dedup_dicts(current[key])
        elif data[key]:
            current[key] = data[key]

    # Pick the earlier published date
    # and the later modified date
    current["published"] = (
        min(
            datetime.strptime(
                current["published"].replace("+00:00", ""), "%Y-%m-%dT%H:%M:%SZ"
            ),
            datetime.strptime(
                data["published"].replace("+00:00", ""), "%Y-%m-%dT%H:%M:%SZ"
            ),
        ).isoformat("T", timespec="seconds")
        + "Z"
    )

    current["modified"] = (
        max(
            datetime.strptime(
                current["modified"].replace("+00:00", ""), "%Y-%m-%dT%H:%M:%SZ"
            ),
            datetime.strptime(
                data["modified"].replace("+00:00", ""), "%Y-%m-%dT%H:%M:%SZ"
            ),
        ).isoformat("T", timespec="seconds")
        + "Z"
    )

    no_important_changes = True
    # One of the important keys has changed
    for key in ["affected", "references", "related", "published"]:
        if canonicaljson.encode_canonical_json(
            original[key]
        ) != canonicaljson.encode_canonical_json(current[key]):
            no_important_changes = False
            break

    if no_important_changes:
        return None

    # If there were important changes, but modified hasn't changed
    # bump the timestamp so downstream can pick up changes
    if original["modified"] == current["modified"]:
        current["modified"] = datetime.now().isoformat("T", timespec="seconds") + "Z"

    return current


def fetch_cve_metadata(PHOTON_VERSIONS):
    cve_metadata = {}
    for branch in PHOTON_VERSIONS:
        url = f"https://packages.vmware.com/photon/photon_cve_metadata/cve_data_photon{branch}.0.json"
        req = urllib.request.Request(url, headers=HEADERS)
        cve_list = None
        try:
            with urllib.request.urlopen(req) as r:
                cve_list = json.loads(r.read().decode())
                with open(f"photon_cve_metadata/{branch}.0.json", "wb") as f:
                    f.write(canonicaljson.encode_canonical_json(cve_list))
        except urllib.error.HTTPError as err:
            if err.code == 404:
                print(f"[-] No CVE metadata for Photon OS {branch}, loading from cache")
                with open(f"photon_cve_metadata/{branch}.0.json", "r") as f:
                    cve_list = json.load(f)
        finally:
            for row in cve_list:
                row["os"] = branch
                cve = row.pop("cve_id")
                if (
                    row["aff_ver"]
                    == f"all versions before {row['res_ver']} are vulnerable"
                ):
                    del row["aff_ver"]
                elif row["status"] != "Not Affected":
                    print(row)
                    raise Exception("Unimplemented affected version range")
                if cve in cve_metadata:
                    cve_metadata[cve].append(row)
                else:
                    cve_metadata[cve] = [row]
            print(
                f"[+] CVE metadata for Photon OS {branch}.0: Added {len(cve_list)} CVEs"
            )

    return cve_metadata


def __main__(advisory_id=None):
    cve_metadata = fetch_cve_metadata(PHOTON_VERSIONS)
    advisories = set()

    for d in get_osv(cve_metadata):
        advisories.add(d["id"])
        # If we are only running for a single advisory
        # Check and continue if it doesn't match
        if advisory_id and d["id"] != advisory_id:
            continue
        fn = f"advisories/{d['id']}.json"
        if os.path.exists(fn):
            d = merge_advisories(fn, d)
        if d:
            with open(fn, "wb") as f:
                f.write(canonicaljson.encode_pretty_printed_json(d))

    # Remove any advisories that are no longer in the upstream data
    for advisory in os.listdir("advisories"):
        if advisory.endswith(".json"):
            if advisory[:-5] not in advisories:
                print(f"[-] Removing {advisory}")
                # os.unlink(f"advisories/{advisory}")


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        __main__(sys.argv[1])
    else:
        __main__()
