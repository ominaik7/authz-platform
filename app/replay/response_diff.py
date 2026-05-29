
from difflib import SequenceMatcher
from .replay_models import ReplayFinding

class ResponseDiffer:

    @staticmethod
    def compare(
        original_response,
        replay_response,
        original_role: str,
        replay_role: str,
        endpoint: str,
    ):

        findings = []

        if (
            original_response.status_code == 200
            and replay_response.status_code == 200
        ):

            similarity = SequenceMatcher(
                None,
                original_response.body,
                replay_response.body,
            ).ratio()

            if similarity > 0.90:
                findings.append(
                    ReplayFinding(
                        finding_type="possible_vertical_privilege_escalation",
                        severity="high",
                        description="Lower privileged role received highly similar response",
                        original_role=original_role,
                        replay_role=replay_role,
                        endpoint=endpoint,
                        evidence={"similarity": similarity},
                    )
                )

        return findings
