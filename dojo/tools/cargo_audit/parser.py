import json
import hashlib
from dojo.models import Finding


class CargoAuditParser(object):
    """
    A class that can be used to parse the cargo audit JSON report file
    """

    def get_scan_types(self):
        return ["CargoAudit Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "CargoAudit Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON output for cargo audit scan report."

    def get_findings(self, filename, test):
        data = json.load(filename)
        dupes = {}
        if data.get('vulnerabilities'):
            for item in data.get('vulnerabilities').get('list'):
                advisory = item.get('advisory')
                vuln_id = advisory.get('id')
                title = advisory.get('title')
                description = "\n".join([
                    f"**Description:** `{advisory.get('description')}`",
                    f"\n**Read more:** `{advisory.get('url')}`",
                ])
                date = advisory.get('date')
                cve = advisory.get('aliases')[0]
                package_name = item.get('package').get('name')
                package_version = item.get('package').get('version')
                severity = "High"
                if 'keywords' in advisory:
                    tags = advisory.get('keywords')
                else:
                    tags = []

                dupe_key = hashlib.sha256(
                    (vuln_id + cve + date + package_name + package_version).encode('utf-8')
                ).hexdigest()

                if dupe_key in dupes:
                    finding = dupes[dupe_key]
                    finding.nb_occurences += 1
                else:
                    finding = Finding(
                        title=title,
                        test=test,
                        severity=severity,
                        cve=cve,
                        tags=tags,
                        description=description,
                        component_name=package_name,
                        component_version=package_version,
                        vuln_id_from_tool=vuln_id,
                        publish_date=date,
                        nb_occurences=1,
                    )
                    dupes[dupe_key] = finding
        return list(dupes.values())

def get_fields(self) -> list[str]:
    """Return the list of fields used in the Cargo Audit Parser.

    Fields:
    - title: Set to the title from Cargo Audit Scanner
    - severity: Set to "High" regardless of context.
    - cve: Set to the cve from Cargo Audit Scanner
    - tags: Set to the tags from Cargo Audit Scanner if they are provided.
    - description: Set to the description from Cargo Audit Scanner and joined with URL provided.
    - component_name: Set to name of package provided by the Cargo Audit Scanner.
    - component_version: Set to version of package provided by the Cargo Audit Scanner.
    - vuln_id_from_tool: Set to id provided by the Cargo Audit Scanner.
    - publish_date: Set to date provided by the Cargo Audit Scanner.
    - nb_occurences: Set to 1 by the parser.

    NOTE: This parser supports tags
    """
    return [
        "title",
        "severity",
        "cve",
        "tags",
        "description",
        "component_name",
        "component_version",
        "vuln_id_from_tool",
        "publish_date",
        "nb_occurences",
    ]
def get_dedupe_fields(self) -> list[str]:
    """Return the list of fields used for deduplication in the Cargo Audit Parser.

    Fields:
    - vulnerability_ids: 
    - severity: Set to "High" regardless of context.
    - component_name: Set to name of package provided by the Cargo Audit Scanner.
    - component_version: Set to version of package provided by the Cargo Audit Scanner.
    - vuln_id_from_tool: Set to id provided by the Cargo Audit Scanner.

    """
    #NOTE: uses legacy dedupe: ['title', 'cwe', 'line', 'file_path', 'description']
    #NOTE: Dedupe fields in settings.dist.py list vuln_id and vuln_id_from_tool

    return [
        "vulnerability_ids",
        "severity",
        "component_name",
        "component_version",
        "vuln_id_from_tool",
    ]
