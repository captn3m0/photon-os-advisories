import sys
import markdown
import json
import os
import re
from bs4 import BeautifulSoup

# This is a WIP unused script to
# write data back to the GSD database
advisories_dir = sys.argv[1]
gsd_dir = sys.argv[2]

CVE_REGEX = r"CVE-\d{4}-\d{4,7}"
FILE_FORMAT = "/Security-Updates-{version}.md"
ADVISORY_URL = "https://github.com/vmware/photon/wiki/Security-Update-{slug}"
PHOTON_VERSIONS = range(1, 5)

def advisory_slug(os_version, advisory):
    _id = int(advisory.split("-")[2])
    return f"{os_version}.0-{_id}"

def generate_cve_mapping():
    mapping = {}
    for version in PHOTON_VERSIONS:
        filename = FILE_FORMAT.format(version=version)
        file = advisories_dir + filename
        with open(file, "r") as f:
            table_html = markdown.markdown(
                f.read(), extensions=["markdown.extensions.tables"]
            )
            soup = BeautifulSoup(table_html, "html.parser")
            for tr in soup.find("tbody").find_all("tr"):
                (advisory, severity, date, packages, cves) = [
                    x.text for x in tr.find_all("td")
                ]
                cves = re.findall(CVE_REGEX, cves)
                for cve in cves:
                    slug = advisory_slug(version, advisory)
                    if cve in mapping:
                        mapping[cve].append(slug)
                    else:
                        mapping[cve] = [slug]

    return mapping


def __main__():
    mapping = generate_cve_mapping()
    for cve in mapping:
        (_, year, _id) = cve.split("-")
        grouping_id = _id[:-3] + "xxx"
        gsd = f"GSD-{year}-{_id}"
        path = f"{gsd_dir}/{year}/{grouping_id}/{gsd}.json"
        if os.path.exists(path):
            updated = False
            data = None
            with open(path, "r") as f:
                data = json.loads(f.read())
                slugs = mapping[cve]
                urls = [ADVISORY_URL.format(slug=slug) for slug in slugs]
                if 'gsd' in data:
                    existing_links = [x['url'] for x in data['gsd']['references']]
                    missing_links = existing_links - urls
                    if len(missing_links) > 0:
                        for url in urls:
                            data['gsd']['references'].append({
                                "type": "ADVISORY",
                                "url": url
                            })
                elif 'GSD' in data and 'references' in data['GSD']:
                    data['GSD']['references'].extend(urls)
                elif 'GSD' in data:
                    data['GSD']['references'] = urls
                else:
                    try:
                        description = data['namespaces']['cve.org']['description']['description_data'][0]['value']
                    except KeyError:
                        description = data['namespaces']['nvd.nist.gov']['cve']['description']['description_data'][0]['value']
                    data['GSD'] = {
                        "alias": cve,
                        "description": description,
                        "id": gsd,
                        "references": urls
                    }
            with open(path, 'w') as f:
                f.write(json.dumps(data, indent=4))

        else:
            print(f"Could not find {cve}")


if __name__ == "__main__":
    __main__()
