
import re

from dataclasses import dataclass


CVE_PATTERN = re.compile(
    r'\bCVE-\d{4}-\d{4,}\b',
    re.IGNORECASE,
)

SENTENCE_BOUNDARY = re.compile(
    r'(?<=[.!?])\s+(?=[A-Z0-9])'
)

AMBIGUOUS_PATTERN = re.compile(
    r'\b(?:one of|some of|either|at least one|'
    r'one vulnerability|one of the vulnerabilities)\b',
    re.IGNORECASE,
)

BOTH_PATTERN = re.compile(
    r'\b(?:both|these two|the two)\b',
    re.IGNORECASE,
)

ALL_PATTERN = re.compile(
    r'\b(?:all|these vulnerabilities|'
    r'the vulnerabilities)\b',
    re.IGNORECASE,
)

SINGULAR_PATTERN = re.compile(
    r'\b(?:this|the|that)\s+'
    r'(?:(?:new|recent|critical|affected)\s+)?'
    r'(?:vulnerability|flaw|issue|bug)\b',
    re.IGNORECASE,
)


@dataclass
class EvidenceCheck:
    valid: bool
    reason: str


class EvidenceContextValidator:
    MAX_PREVIOUS_SENTENCES = 2

    @classmethod
    def check(
        cls,
        article_text: str,
        cve: str | None,
        quote: str | None,
    ) -> EvidenceCheck:
        if not cve or not quote:
            return EvidenceCheck(
                valid=False,
                reason='Missing CVE or evidence',
            )

        target = cve.upper()
        normalized_article = cls._normalize(article_text)
        normalized_quote = cls._normalize(quote)

        if not normalized_quote:
            return EvidenceCheck(
                valid=False,
                reason='Empty evidence',
            )

        sentences = cls._split_sentences(normalized_article)

        matching_indices = [
            index
            for index, sentence in enumerate(sentences)
            if normalized_quote.lower() in sentence.lower()
        ]

        if not matching_indices:
            return EvidenceCheck(
                valid=False,
                reason='Evidence not found in article',
            )

        for index in matching_indices:
            result = cls._check_sentence(
                sentences=sentences,
                index=index,
                target=target,
            )

            if result.valid:
                return result

        return EvidenceCheck(
            valid=False,
            reason='Evidence is not linked to target CVE',
        )

    @classmethod
    def _check_sentence(
        cls,
        sentences: list[str],
        index: int,
        target: str,
    ) -> EvidenceCheck:
        sentence = sentences[index]
        current_cves = cls._extract_cves(sentence)

        if AMBIGUOUS_PATTERN.search(sentence):
            return EvidenceCheck(
                valid=False,
                reason='Ambiguous vulnerability reference',
            )

        if current_cves:
            if len(current_cves) == 1:
                if target in current_cves:
                    return EvidenceCheck(
                        valid=True,
                        reason='Direct CVE evidence',
                    )

                return EvidenceCheck(
                    valid=False,
                    reason='Evidence refers to another CVE',
                )

            if cls._is_collective(
                sentence,
                len(current_cves),
            ):
                if target in current_cves:
                    return EvidenceCheck(
                        valid=True,
                        reason='Explicit group evidence',
                    )

            return EvidenceCheck(
                valid=False,
                reason='Multiple CVEs without clear group evidence',
            )

        if cls._has_group_reference(sentence):
            return cls._resolve_previous(
                sentences=sentences,
                index=index,
                target=target,
                collective=True,
            )

        if SINGULAR_PATTERN.search(sentence):
            return cls._resolve_previous(
                sentences=sentences,
                index=index,
                target=target,
                collective=False,
            )

        return EvidenceCheck(
            valid=False,
            reason='No explicit CVE reference',
        )

    @classmethod
    def _resolve_previous(
        cls,
        sentences: list[str],
        index: int,
        target: str,
        collective: bool,
    ) -> EvidenceCheck:
        start = max(
            0,
            index - cls.MAX_PREVIOUS_SENTENCES,
        )

        for previous_index in range(index - 1, start - 1, -1):
            previous = sentences[previous_index]
            previous_cves = cls._extract_cves(previous)

            if not previous_cves:
                continue

            if collective:
                if not cls._is_collective(
                    sentences[index],
                    len(previous_cves),
                ):
                    return EvidenceCheck(
                        valid=False,
                        reason='Group reference does not match CVE count',
                    )
            else:
                if len(previous_cves) != 1:
                    return EvidenceCheck(
                        valid=False,
                        reason='Singular reference has ambiguous antecedent',
                    )

            if target in previous_cves:
                return EvidenceCheck(
                    valid=True,
                    reason=(
                        'Group reference resolved'
                        if collective
                        else 'Singular reference resolved'
                    ),
                )

            return EvidenceCheck(
                valid=False,
                reason='Target CVE is not in referenced context',
            )

        return EvidenceCheck(
            valid=False,
            reason='No nearby CVE reference found',
        )

    @staticmethod
    def _extract_cves(text: str) -> set[str]:
        return {
            match.group().upper()
            for match in CVE_PATTERN.finditer(text)
        }

    @staticmethod
    def _has_group_reference(text: str) -> bool:
        return bool(
            BOTH_PATTERN.search(text)
            or ALL_PATTERN.search(text)
        )

    @staticmethod
    def _is_collective(
        text: str,
        cve_count: int,
    ) -> bool:
        if cve_count < 2:
            return False

        if AMBIGUOUS_PATTERN.search(text):
            return False

        if BOTH_PATTERN.search(text):
            return cve_count == 2

        if ALL_PATTERN.search(text):
            return True

        return False

    @staticmethod
    def _split_sentences(text: str) -> list[str]:
        return [
            sentence.strip()
            for sentence in SENTENCE_BOUNDARY.split(text)
            if sentence.strip()
        ]

    @staticmethod
    def _normalize(text: str) -> str:
        return ' '.join(text.split())