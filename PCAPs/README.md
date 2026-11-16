# Network Intrusion PCAP Dataset

**Security Warning:** These archives contain real-world network captures of malware infections sourced from [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/). **Do not extract or analyze these files outside of an isolated Virtual Machine.**

To keep the Git repository lightweight, the raw password-protected `.pcap.zip` archives are hosted under this repository's **[GitHub Releases (v1.0-pcaps)](https://github.com/IqramulHaqueTanim/Network-Traffic-Analysis/releases/tag/v1.0-pcaps)**.

### Dataset Inventory & Integrity Checksums

| Case | Archive Filename | Size | Zip Password | Zip SHA-256 Checksum |
| :--- | :--- | :--- | :--- | :--- |
| **Case 01** | `2026-10-01-traffic-analysis-exercise.pcap.zip` | 33.1 MB | `infected_20261001` | `FFC811C2D1E990EE6E008CAF2DF926ECB9E3AEED3DD0032E6E03ED085A6647BC` |
| **Case 02** | `2026-08-09-traffic-analysis-exercise.pcap.zip` | 12.8 MB | `infected_20260809` | `676BF6B5F269A8DA49E8DA6B6DCB3AED0CA2629F99005DC39F4B887AD9BEE822` |
| **Case 03** | `2026-09-11-traffic-analysis-exercise.pcap.zip` | 54.6 MB | `infected_20260911` | `2406E67624B3C86E73929D552F472E157C496EE56BDDE6E2299A481B90210AB0` |

### Verification & Extraction (Linux / Kali VM)
1. Download the archives from the [Releases page](https://github.com/IqramulHaqueTanim/Network-Traffic-Analysis/releases/tag/v1.0-pcaps) into an isolated VM.
2. Verify archive integrity before unzipping:

~~~~bash
sha256sum *.pcap.zip
~~~~

3. Extract the `.pcap` files using the corresponding archive password:

~~~~bash
unzip -P infected_20261001 2026-10-01-traffic-analysis-exercise.pcap.zip
unzip -P infected_20260809 2026-08-09-traffic-analysis-exercise.pcap.zip
unzip -P infected_20260911 2026-09-11-traffic-analysis-exercise.pcap.zip
~~~~
