import re


CVE_PATTERN = re.compile(
    r'\bCVE-\d{4}-\d{4,}\b',
    re.IGNORECASE,
)


class CVEExtractor:
    def extract(
        self,
        text: str,
    ) -> list[str]:
        if not text:
            return []

        cves = {
            match.upper()
            for match in CVE_PATTERN.findall(text)
        }

        return sorted(cves)