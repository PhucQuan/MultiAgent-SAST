"""AI-only workflow for normalized mock findings."""

from typing import List

from aegis_sast.ai.schemas import AIExecutionSummary
from aegis_sast.orchestration.ai_nodes import (
    AuditorAgentNode,
    JudgeAgentNode,
    KnowledgeLoaderAgentNode,
    PlannerAgentNode,
    ReporterAgentNode,
    SkepticAgentNode,
)
from aegis_sast.orchestration.contracts import (
    AuditorInput,
    JudgeInput,
    KnowledgeLoaderNodeInput,
    PlannerInput,
    ReporterInput,
    SkepticInput,
)
from aegis_sast.orchestration.state import AgentWorkflowState
from aegis_sast.triage.schema import AITriageInput, TriageDecision


class AITriageWorkflow:
    """Run planner, knowledge, auditor, optional skeptic, judge, and reporter."""

    def __init__(
        self,
        *,
        planner: PlannerAgentNode | None = None,
        knowledge_loader: KnowledgeLoaderAgentNode | None = None,
        auditor: AuditorAgentNode | None = None,
        skeptic: SkepticAgentNode | None = None,
        judge: JudgeAgentNode | None = None,
        reporter: ReporterAgentNode | None = None,
    ):
        self.planner = planner or PlannerAgentNode()
        self.knowledge_loader = knowledge_loader or KnowledgeLoaderAgentNode()
        self.auditor = auditor or AuditorAgentNode()
        self.skeptic = skeptic or SkepticAgentNode()
        self.judge = judge or JudgeAgentNode()
        self.reporter = reporter or ReporterAgentNode()

    def run_one(self, triage_input: AITriageInput) -> TriageDecision:
        """Run one normalized finding through the AI workflow."""
        route_taken: List[str] = ["planner"]
        plan = self.planner.plan(PlannerInput(triage_input=triage_input))

        route_taken.append("knowledge_loader")
        knowledge = self.knowledge_loader.load(
            KnowledgeLoaderNodeInput(triage_input=triage_input, plan=plan)
        )

        route_taken.append("auditor")
        auditor_result = self.auditor.audit(
            AuditorInput(
                triage_input=triage_input,
                plan=plan,
                knowledge=knowledge,
            )
        )

        skeptic_result = None
        if plan.should_use_skeptic:
            route_taken.append("skeptic_validator")
            skeptic_result = self.skeptic.review(
                SkepticInput(
                    triage_input=triage_input,
                    auditor_result=auditor_result,
                    knowledge=knowledge,
                )
            )

        route_taken.append("judge")
        decision = self.judge.decide(
            JudgeInput(
                triage_input=triage_input,
                plan=plan,
                auditor_result=auditor_result,
                skeptic_result=skeptic_result,
                route_taken=route_taken.copy(),
            )
        )

        route_taken.append("reporter")
        enrichment = self.reporter.enrich(
            ReporterInput(
                triage_input=triage_input,
                decision=decision,
                knowledge=knowledge,
            )
        )
        decision.metadata["report_enrichment"] = enrichment.to_dict()
        decision.metadata["knowledge_card_id"] = knowledge.selection.card_id
        decision.metadata["planner"] = plan.to_dict()
        return decision

    def run_batch(self, triage_inputs: list[AITriageInput]) -> AgentWorkflowState:
        """Run a batch and return state with decisions and execution summary."""
        state = AgentWorkflowState(triage_inputs=triage_inputs)
        summary = AIExecutionSummary()
        decisions = []
        for triage_input in triage_inputs:
            try:
                decision = self.run_one(triage_input)
                decisions.append(decision.to_dict())
                summary.add_decision(decision)
            except Exception as exc:
                state.errors.append(f"{triage_input.finding.finding_id}: {exc}")

        state.metadata["decisions"] = decisions
        state.metadata["execution_summary"] = summary.to_dict()
        state.add_trace(
            "ai_workflow",
            f"Processed {len(triage_inputs)} normalized AI findings.",
            metadata=summary.to_dict(),
        )
        return state
