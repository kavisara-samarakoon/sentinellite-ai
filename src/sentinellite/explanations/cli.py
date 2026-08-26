from collections.abc import Iterable

from rich.panel import Panel
from rich.pretty import Pretty
from rich.table import Table
from rich.text import Text

from sentinellite.explanations.models import AlertExplanation


def explanation_has_displayable_evidence(explanation: AlertExplanation) -> bool:
    """Return whether an explanation has evidence to show in the terminal."""
    return bool(explanation.evidence_summary)


def build_explanation_panel(explanation: AlertExplanation) -> Panel:
    """Build a readable Rich panel without changing the explanation."""
    content = Table.grid(padding=(0, 1))
    content.add_column(style="bold cyan", no_wrap=True)
    content.add_column()

    content.add_row("Rule ID", Text(explanation.rule_id))
    content.add_row("Title", Text(explanation.title))
    content.add_row("Summary", Text(explanation.summary))
    content.add_row("Why it matched", Text(explanation.why_it_matched))
    content.add_row("Confidence", Text(explanation.confidence.upper()))

    content.add_row("Possible causes", "")
    for cause in explanation.possible_causes:
        content.add_row("", Text(f"• {cause}"))

    content.add_row("Recommended actions", "")
    for action in explanation.recommended_actions:
        content.add_row("", Text(f"• {action}"))

    if explanation_has_displayable_evidence(explanation):
        content.add_row(
            "Evidence summary",
            Pretty(dict(explanation.evidence_summary), expand_all=True),
        )

    return Panel.fit(content, title="Alert Explanation", border_style="cyan")


def build_explanation_panels(
    explanations: Iterable[AlertExplanation],
) -> list[Panel]:
    """Build one panel per explanation while preserving input order."""
    return [build_explanation_panel(explanation) for explanation in explanations]
