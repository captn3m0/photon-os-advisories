# VMWare Photon Advisories

## Background

- [VMWare Photon](https://vmware.github.io/photon) is a minimal linux container host OS.
- Photon Security Advisories are published by VMWare at https://github.com/vmware/photon/wiki/Security-Advisories.
- [OSV](https://ossf.github.io/osv-schema/) is a Open Source Vulnerability format, as specified by the [Open Source Security Foundation](https://openssf.org).

## What is this project?

The OSV.dev expects advisories to be published in the OSV format. This repository
republishes the advisories in the OSV format

- [x] Picks up data from https://github.com/vmware/photon/wiki/Security-Advisories,
- [x] Get CVE metadata from https://packages.vmware.com/photon/photon_cve_metadata/
- [x] Generates advisories in the OSV format at `advisories/` using the above.

## TODO:

- [x] Delete advisories that are deleted upstream (Experimental)
- [x] Automatic Update
- [ ] Schema: Provide `credits`
- [x] Schema: Provide impacted packages
- [x] Schema: Provide all impacted packages, with version number that fixes the issue. (Available in all but 50-60 advisories)
- [ ] Schema: Provide summary/details/severity
- [ ] Schema: Provide SHA256 hashes under database_specific

## Contributing

Contributions are welcome! Since the advisories are automatically generated, please don't make
manual updates to the JSON advisory files. Instead update the generation script: `generate.py`.

## License

Licensed under the [MIT License](https://nemo.mit-license.org/). See LICENSE file for details.