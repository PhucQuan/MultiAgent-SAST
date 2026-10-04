"""Knowledge Loader — nạp tối đa 2 card để tránh knowledge bias."""

from ..knowledge.loader import knowledge_loader
from ..schemas.state import GraphState


def knowledge_loader_node(state: GraphState) -> GraphState:
    new_state = state.model_copy(deep=True)
    if new_state.triage_state:
        return new_state
    cards = knowledge_loader.load(
        state.finding.cwe, state.finding.language.value, max_cards=2
    )
    new_state.knowledge_cards = [c.model_dump() for c in cards]
    return new_state
