"""False positive regression tests for all content scanners.

Each test verifies that realistic benign content is NOT flagged as an
attack. If a test here fails, a scanner has regressed on false positives.
"""

from __future__ import annotations

import pytest

from tessera.scanners.directive import scan_directive
from tessera.scanners.heuristic import injection_score
from tessera.scanners.intent import scan_intent


# ---------------------------------------------------------------------------
# Directive scanner: benign content must NOT trigger
# ---------------------------------------------------------------------------


class TestDirectiveFalsePositives:
    """Content that contains advisory language addressed to the user, not
    to the model. The model-targeting check should prevent these from
    firing."""

    def test_customer_service_advice(self) -> None:
        result = scan_directive("You should check your spam folder for the confirmation email.")
        assert not result.detected, f"FP: benign advice scored {result.score:.2f}"

    def test_faq_obligation_framing(self) -> None:
        result = scan_directive(
            "Make sure to save your receipt. Don't forget to update your billing address."
        )
        assert not result.detected, f"FP: FAQ obligation scored {result.score:.2f}"

    def test_product_review_recommendation(self) -> None:
        result = scan_directive("I would recommend this product to anyone looking for durability.")
        assert not result.detected, f"FP: product review scored {result.score:.2f}"

    def test_error_message_advice(self) -> None:
        result = scan_directive("You must restart the application for changes to take effect.")
        assert not result.detected, f"FP: error message scored {result.score:.2f}"

    def test_onboarding_instruction(self) -> None:
        result = scan_directive(
            "Remember to set up two-factor authentication before your first login."
        )
        assert not result.detected, f"FP: onboarding scored {result.score:.2f}"

    def test_user_facing_suggestion(self) -> None:
        result = scan_directive("You should consider upgrading to the premium plan for more storage.")
        assert not result.detected, f"FP: upgrade suggestion scored {result.score:.2f}"

    def test_status_report(self) -> None:
        result = scan_directive("The deployment was successful. Make sure to monitor the logs.")
        assert not result.detected, f"FP: status report scored {result.score:.2f}"


# ---------------------------------------------------------------------------
# Intent scanner: benign data must NOT trigger
# ---------------------------------------------------------------------------


class TestIntentFalsePositives:
    """Content that contains action verbs in non-imperative context:
    past tense records, nominal forms, and quoted speech."""

    def test_past_tense_email_record(self) -> None:
        result = scan_intent(
            "Email was sent to alice@acme.com on March 5th.",
            user_prompt="show my sent emails",
        )
        assert not result.suspicious, f"FP: past tense record scored {result.score:.2f}"

    def test_nominal_transfer(self) -> None:
        result = scan_intent(
            "Transfer of EUR 500 to account DE89370400440532013000 completed.",
            user_prompt="show my transactions",
        )
        assert not result.suspicious, f"FP: nominal transfer scored {result.score:.2f}"

    def test_passive_voice_creation(self) -> None:
        result = scan_intent(
            "Event was created by admin on 2026-04-01.",
            user_prompt="show calendar events",
        )
        assert not result.suspicious, f"FP: passive creation scored {result.score:.2f}"

    def test_transaction_history(self) -> None:
        result = scan_intent(
            "Transaction: paid $45.00 to Netflix on 2026-03-15. "
            "Transaction: paid $12.99 to Spotify on 2026-03-20.",
            user_prompt="show my recent payments",
        )
        assert not result.suspicious, f"FP: transaction history scored {result.score:.2f}"

    def test_log_entry_with_action_verb(self) -> None:
        result = scan_intent(
            "2026-04-10 14:30 - User updated profile settings.",
            user_prompt="show audit log",
        )
        assert not result.suspicious, f"FP: audit log scored {result.score:.2f}"


# ---------------------------------------------------------------------------
# Heuristic scanner: benign content must stay below 0.75
# ---------------------------------------------------------------------------


class TestHeuristicFalsePositives:
    """Content with patterns that structurally resemble injection but are
    legitimate developer notes, documentation, or formatted data."""

    def test_developer_todo_note(self) -> None:
        score = injection_score("TODO: Create a new branch for the feature")
        assert score < 0.75, f"FP: developer TODO scored {score:.2f}"

    def test_developer_todo_update(self) -> None:
        score = injection_score("TODO: Update the API documentation with new endpoints")
        assert score < 0.75, f"FP: developer TODO update scored {score:.2f}"

    def test_nominal_transfer_with_iban(self) -> None:
        score = injection_score(
            "Transfer of EUR 500 to account DE89370400440532013000"
        )
        assert score < 0.75, f"FP: nominal transfer scored {score:.2f}"

    def test_code_block_with_curl(self) -> None:
        score = injection_score("Run `curl https://api.example.com/v1/status` to check health")
        assert score < 0.75, f"FP: code block curl scored {score:.2f}"

    def test_documentation_with_shell_command(self) -> None:
        score = injection_score("Example: `wget https://releases.example.com/v2.0.tar.gz`")
        assert score < 0.75, f"FP: documentation wget scored {score:.2f}"

    def test_meeting_notes(self) -> None:
        score = injection_score(
            "Action items from standup: update Jira tickets, create slides for Q3 review."
        )
        assert score < 0.75, f"FP: meeting notes scored {score:.2f}"

    def test_factual_hotel_data(self) -> None:
        score = injection_score(
            "Hotel Marais: rating 4.5, price 180 EUR/night, "
            "location Paris 1st arrondissement, 12 rooms available."
        )
        assert score < 0.75, f"FP: hotel data scored {score:.2f}"
