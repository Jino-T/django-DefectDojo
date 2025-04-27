import logging

from defusedxml import ElementTree

from dojo.models import Finding

logger = logging.getLogger(__name__)


class BurpDastardlyParser:

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Burp Dastardly Parser

        Fields:
        - title: Set to message from Burp Scanner.
        - url: Set to name from Burp Scanner.
        - severity: Set to type from Burp Scanner.
        - description: Set to text from Burp Scanner.
        - false_p: Set to false.
        - duplicate: Set to false.
        - out_of_scope: Set to false.
        - mitigated: Set to none.
        - dynamic_finding: Set to true.
        """
        return [
            "title",
            "url",
            "severity",
            "description",
            "false_p",
            "duplicate",
            "out_of_scope",
            "mitigated",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of dedupe fields used in the Burp Dastardly Parser

        Fields:
        - title: Set to message from Burp Scanner.
        - severity: Set to type from Burp Scanner.

        NOTE: vuln_id_from_tool is not provided by parser
        """
        return [
            "title",
            "severity",
        ]

    def get_scan_types(self):
        return ["Burp Dastardly Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Burp Dastardly Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import Burp Dastardly XML files."
        )

    def get_findings(self, xml_output, test):
        tree = ElementTree.parse(xml_output, ElementTree.XMLParser())
        return self.get_items(tree, test)

    def get_items(self, tree, test):
        items = []
        for node in tree.findall("testsuite"):
            if int(node.attrib["failures"]) != 0:
                name = node.attrib["name"]
                testcase = node.findall("testcase")
                for case in testcase:
                    for fail in case.findall("failure"):
                        title = fail.attrib["message"]
                        severity = fail.attrib["type"]
                        description = fail.text
                        finding = Finding(
                            title=title,
                            url=name,
                            test=test,
                            severity=severity,
                            description=description,
                            false_p=False,
                            duplicate=False,
                            out_of_scope=False,
                            mitigated=None,
                            dynamic_finding=True,
                        )
                        items.append(finding)
        return items
