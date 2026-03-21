"""Tests for conflict_explanations module."""

from src.conflict_analyzer import ConflictType, ConflictResult
from src.conflict_explanations import (
    get_explanation,
    format_explanation_for_report,
    get_all_conflict_types,
    CONFLICT_TEMPLATES,
    ConflictExplanation
)


class TestConflictExplanations:
    """Tests for conflict explanations."""

    def test_all_conflict_types_have_explanations(self):
        """Test that all conflict types have explanation templates."""
        for conflict_type in ConflictType:
            assert conflict_type in CONFLICT_TEMPLATES, \
                f"Missing explanation for {conflict_type}"

    def test_explanation_has_required_fields(self):
        """Test that each explanation has all required fields."""
        for conflict_type, explanation in CONFLICT_TEMPLATES.items():
            assert explanation.title, f"Missing title for {conflict_type}"
            assert explanation.what_is_happening, \
                f"Missing what_is_happening for {conflict_type}"
            assert explanation.why_problematic, \
                f"Missing why_problematic for {conflict_type}"
            assert explanation.how_to_fix, \
                f"Missing how_to_fix for {conflict_type}"
            assert explanation.side_effects, \
                f"Missing side_effects for {conflict_type}"

    def test_explanation_how_to_fix_contains_commands(self):
        """Test that how_to_fix contains RouterOS commands."""
        for conflict_type, explanation in CONFLICT_TEMPLATES.items():
            # At least some entries should contain RouterOS commands
            has_commands = any(
                '/' in line or '#' in line
                for line in explanation.how_to_fix
            )
            assert has_commands, \
                f"how_to_fix should contain commands for {conflict_type}"

    def test_get_explanation_returns_template(self):
        """Test that get_explanation returns correct template."""
        conflict = ConflictResult(
            conflict_type=ConflictType.UNREACHABLE_RULE,
            severity="High",
            title="Test",
            description="Test description"
        )

        explanation = get_explanation(conflict)

        assert isinstance(explanation, ConflictExplanation)
        assert explanation.title == CONFLICT_TEMPLATES[ConflictType.UNREACHABLE_RULE].title

    def test_get_explanation_unknown_type(self):
        """Test that unknown conflict type gets generic explanation."""
        # Create a mock conflict with unknown type
        conflict = ConflictResult(
            conflict_type=ConflictType.DUPLICATE_RULE,  # Use existing type
            severity="Low",
            title="Unknown conflict",
            description="Some description"
        )

        explanation = get_explanation(conflict)

        assert isinstance(explanation, ConflictExplanation)
        assert "Unknown conflict" in explanation.title or explanation.title

    def test_format_explanation_for_report_returns_html(self):
        """Test that format_explanation_for_report returns HTML."""
        conflict = ConflictResult(
            conflict_type=ConflictType.ORPHAN_ROUTING_MARK,
            severity="Medium",
            title="Test orphan mark",
            description="Test description"
        )

        html = format_explanation_for_report(conflict)

        assert isinstance(html, str)
        assert "<h3>" in html
        assert "<p>" in html
        assert "<pre><code>" in html

    def test_format_explanation_includes_references(self):
        """Test that formatted explanation includes references."""
        conflict = ConflictResult(
            conflict_type=ConflictType.NAT_BYPASSES_FIREWALL,
            severity="High",
            title="Test NAT bypass",
            description="Test description"
        )

        html = format_explanation_for_report(conflict)

        # Should have references section if template has references
        template = CONFLICT_TEMPLATES[ConflictType.NAT_BYPASSES_FIREWALL]
        if template.references:
            assert "<strong>Ссылки:</strong>" in html or "references" in html.lower()

    def test_get_all_conflict_types_returns_list(self):
        """Test that get_all_conflict_types returns list of all types."""
        types = get_all_conflict_types()

        assert isinstance(types, list)
        assert len(types) == len(ConflictType)

        for conflict_type in ConflictType:
            assert conflict_type in types

    def test_explanation_title_is_descriptive(self):
        """Test that explanation titles are descriptive."""
        for conflict_type, explanation in CONFLICT_TEMPLATES.items():
            # Title should be in Russian and descriptive
            assert len(explanation.title) > 10, \
                f"Title too short for {conflict_type}"
            assert len(explanation.title) < 100, \
                f"Title too long for {conflict_type}"

    def test_explanation_what_is_happening_is_detailed(self):
        """Test that what_is_happening provides sufficient detail."""
        for conflict_type, explanation in CONFLICT_TEMPLATES.items():
            # Should be 2-3 sentences
            sentences = explanation.what_is_happening.count('.') + \
                       explanation.what_is_happening.count('!')
            assert sentences >= 2, \
                f"what_is_happening too brief for {conflict_type}"

    def test_explanation_side_effects_warns_user(self):
        """Test that side_effects provides useful warnings."""
        for conflict_type, explanation in CONFLICT_TEMPLATES.items():
            # Should mention potential issues
            text = explanation.side_effects.lower()
            has_warning = any(
                word in text
                for word in ['убедитесь', 'может', 'проверь', 'осторож', 'вниман']
            )
            assert has_warning or len(explanation.side_effects) > 20, \
                f"side_effects should warn user for {conflict_type}"


class TestConflictExplanationDataclass:
    """Tests for ConflictExplanation dataclass."""

    def test_create_explanation(self):
        """Test creating ConflictExplanation."""
        explanation = ConflictExplanation(
            title="Test Title",
            what_is_happening="Something is happening",
            why_problematic="This is bad",
            how_to_fix=["# Do this", "/command"],
            side_effects="May break things",
            references=["https://example.com"]
        )

        assert explanation.title == "Test Title"
        assert len(explanation.how_to_fix) == 2
        assert len(explanation.references) == 1

    def test_create_explanation_empty_references(self):
        """Test creating ConflictExplanation with empty references."""
        explanation = ConflictExplanation(
            title="Test",
            what_is_happening="Test",
            why_problematic="Test",
            how_to_fix=[],
            side_effects="Test",
            references=[]
        )

        assert explanation.references == []
