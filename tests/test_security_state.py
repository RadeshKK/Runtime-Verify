import json
import pytest

from runtimeverify.events.base import Event
from runtimeverify.events.canonical import (
    AgentCommunicationEvent,
    CredentialAccessEvent,
    FilesystemDeleteEvent,
    FilesystemReadEvent,
    FilesystemWriteEvent,
    GitOperationEvent,
    HumanApprovalEvent,
    LLMRequestEvent,
    LLMResponseEvent,
    NetworkRequestEvent,
    PolicyDecisionEvent,
    ProcessCreationEvent,
    ShellCommandEvent,
    ToolCallEvent,
    ToolResultEvent,
)
from runtimeverify.markov.model import MarkovModel
from runtimeverify.sprt.alternative import UniformAlternativeModel
from runtimeverify.sprt.engine import SPRTEngine
from runtimeverify.sprt.hypothesis import Hypothesis
from runtimeverify.state.adapter import MarkovStateAdapter
from runtimeverify.state.base import StateInterface
from runtimeverify.state.categories import StateCategory
from runtimeverify.state.classifier import (
    BaseStateEnricher,
    DeterministicSecurityClassifier,
    SecurityClassificationPipeline,
    SecurityClassifierRegistry,
    classify_event,
)
from runtimeverify.state.context import StateContext
from runtimeverify.state.hierarchy import StateHierarchy
from runtimeverify.state.security import SecurityState
from runtimeverify.state.taxonomy import (
    DEFAULT_SECURITY_RISK_MAP,
    SECURITY_HIERARCHY_PATHS,
    SECURITY_TO_STATE_CATEGORY,
    SecurityRiskLevel,
    SecurityStateCategory,
    get_default_category,
    get_default_hierarchy,
    get_default_risk,
)


class TestSecurityTaxonomy:
    """Verifies the complete 27 canonical security state categories and mappings."""

    REQUIRED_CATEGORIES = [
        "LLM_REQUEST",
        "LLM_RESPONSE",
        "FILE_READ",
        "FILE_WRITE",
        "FILE_DELETE",
        "SHELL_SAFE",
        "SHELL_NETWORK",
        "SHELL_PRIVILEGED",
        "SHELL_DESTRUCTIVE",
        "NETWORK_TRUSTED",
        "NETWORK_UNKNOWN",
        "NETWORK_SENSITIVE",
        "GIT_READ",
        "GIT_COMMIT",
        "GIT_PUSH",
        "PROCESS_CREATE",
        "PROCESS_TERMINATE",
        "SECRET_ACCESS",
        "CREDENTIAL_ACCESS",
        "TOOL_CALL",
        "TOOL_RESULT",
        "AGENT_MESSAGE",
        "AGENT_HANDOFF",
        "HUMAN_APPROVAL",
        "POLICY_ALLOW",
        "POLICY_REVIEW",
        "POLICY_BLOCK",
        "UNKNOWN",
    ]

    def test_all_required_categories_present(self):
        category_values = {cat.value for cat in SecurityStateCategory}
        for req in self.REQUIRED_CATEGORIES:
            assert req in category_values, f"Missing required category: {req}"

    def test_risk_levels(self):
        assert SecurityRiskLevel.INFO.value == "INFO"
        assert SecurityRiskLevel.LOW.value == "LOW"
        assert SecurityRiskLevel.MEDIUM.value == "MEDIUM"
        assert SecurityRiskLevel.HIGH.value == "HIGH"
        assert SecurityRiskLevel.CRITICAL.value == "CRITICAL"

    def test_category_and_hierarchy_mappings(self):
        for cat in SecurityStateCategory:
            state_cat = get_default_category(cat)
            assert isinstance(state_cat, StateCategory)
            assert cat in SECURITY_TO_STATE_CATEGORY

            hierarchy = get_default_hierarchy(cat)
            assert isinstance(hierarchy, StateHierarchy)
            assert len(hierarchy.path) >= 2
            assert cat in SECURITY_HIERARCHY_PATHS

            risk = get_default_risk(cat)
            assert isinstance(risk, SecurityRiskLevel)
            assert cat in DEFAULT_SECURITY_RISK_MAP


class TestSecurityStateModel:
    """Tests the SecurityState model structure, immutability, and StateInterface protocol."""

    def test_security_state_creation_and_defaults(self):
        ctx = StateContext(agent_id="agent-01", session_id="sess-01")
        state = SecurityState(
            security_category=SecurityStateCategory.FILE_READ,
            context=ctx,
        )

        assert state.name == "FILE_READ"
        assert state.security_category == SecurityStateCategory.FILE_READ
        assert state.category == StateCategory.FILESYSTEM
        assert state.hierarchy.path == ["FILESYSTEM", "READ"]
        assert state.dot_path == "FILESYSTEM.READ"
        assert state.risk_level == SecurityRiskLevel.INFO
        assert state.confidence == 1.0
        assert not state.is_high_risk
        assert not state.is_critical

    def test_security_state_high_risk_and_critical(self):
        ctx = StateContext(agent_id="agent-01", session_id="sess-01")
        destr_state = SecurityState(
            security_category=SecurityStateCategory.SHELL_DESTRUCTIVE,
            context=ctx,
        )
        assert destr_state.is_high_risk is True
        assert destr_state.is_critical is True
        assert destr_state.risk_level == SecurityRiskLevel.CRITICAL

        priv_state = SecurityState(
            security_category=SecurityStateCategory.SHELL_PRIVILEGED,
            context=ctx,
        )
        assert priv_state.is_high_risk is True
        assert priv_state.is_critical is False
        assert priv_state.risk_level == SecurityRiskLevel.HIGH

    def test_satisfies_state_interface_protocol(self):
        ctx = StateContext(agent_id="agent-01", session_id="sess-01")
        state = SecurityState(
            security_category=SecurityStateCategory.NETWORK_TRUSTED,
            context=ctx,
        )
        assert isinstance(state, StateInterface)

    def test_immutability(self):
        ctx = StateContext(agent_id="agent-01", session_id="sess-01")
        state = SecurityState(
            security_category=SecurityStateCategory.SHELL_SAFE,
            context=ctx,
        )
        with pytest.raises(Exception):
            state.name = "MODIFIED"

    def test_serialization_and_deserialization(self):
        ctx = StateContext(agent_id="agent-01", session_id="sess-01")
        state = SecurityState(
            security_category=SecurityStateCategory.SHELL_NETWORK,
            context=ctx,
            attributes={"command": "curl https://example.com"},
        )
        json_str = state.model_dump_json()
        data = json.loads(json_str)
        assert data["security_category"] == "SHELL_NETWORK"
        assert data["attributes"]["command"] == "curl https://example.com"

        restored = SecurityState.model_validate_json(json_str)
        assert restored.security_category == SecurityStateCategory.SHELL_NETWORK
        assert restored.attributes["command"] == "curl https://example.com"
        assert isinstance(restored, StateInterface)

    def test_with_enrichment(self):
        ctx = StateContext(agent_id="agent-01", session_id="sess-01")
        initial = SecurityState(
            security_category=SecurityStateCategory.SHELL_SAFE,
            context=ctx,
        )
        enriched = initial.with_enrichment(
            security_category=SecurityStateCategory.SHELL_PRIVILEGED,
            confidence=0.88,
            classifier_source="laya_semantic",
            attributes_update={"reason": "contains sudo equivalent"},
        )

        assert initial.security_category == SecurityStateCategory.SHELL_SAFE
        assert enriched.security_category == SecurityStateCategory.SHELL_PRIVILEGED
        assert enriched.confidence == 0.88
        assert enriched.classifier_source == "laya_semantic"
        assert enriched.attributes["reason"] == "contains sudo equivalent"
        assert enriched.is_high_risk is True


class TestDeterministicClassifier:
    """Tests rule-based deterministic classification across all categories."""

    def setup_method(self):
        self.classifier = DeterministicSecurityClassifier()

    def test_classify_shell_destructive(self):
        destructive_commands = [
            "rm -rf /var/log/*",
            "rm -f -r /tmp/data",
            "rm --force --recursive /",
            "mkfs.ext4 /dev/sdb1",
            "dd if=/dev/zero of=/dev/sda bs=1M",
            "shred -u secret.txt",
            "format C: /fs:NTFS",
            "del /f /s /q C:\\Windows",
        ]
        for cmd in destructive_commands:
            event = ShellCommandEvent(
                agent_id="agent-01",
                session_id="sess-01",
                command=cmd,
            )
            state = self.classifier.classify(event)
            assert state.security_category == SecurityStateCategory.SHELL_DESTRUCTIVE, f"Failed for {cmd}"
            assert state.risk_level == SecurityRiskLevel.CRITICAL
            assert state.attributes["command"] == cmd

    def test_classify_shell_privileged(self):
        privileged_commands = [
            "sudo apt-get update",
            "su - root",
            "chmod 777 /app/exec.sh",
            "chmod +x script.py",
            "chown -R root:root /etc",
            "runas /user:admin cmd.exe",
        ]
        for cmd in privileged_commands:
            event = ShellCommandEvent(
                agent_id="agent-01",
                session_id="sess-01",
                command=cmd,
            )
            state = self.classifier.classify(event)
            assert state.security_category == SecurityStateCategory.SHELL_PRIVILEGED, f"Failed for {cmd}"
            assert state.risk_level == SecurityRiskLevel.HIGH

    def test_classify_shell_network(self):
        network_commands = [
            "curl -X POST https://api.site.com",
            "wget http://downloads.com/archive.tar.gz",
            "nc -nv 10.0.0.1 4444",
            "ssh user@remote-server.com",
            "ping 1.1.1.1",
            "traceroute 8.8.8.8",
        ]
        for cmd in network_commands:
            event = ShellCommandEvent(
                agent_id="agent-01",
                session_id="sess-01",
                command=cmd,
            )
            state = self.classifier.classify(event)
            assert state.security_category == SecurityStateCategory.SHELL_NETWORK, f"Failed for {cmd}"
            assert state.risk_level == SecurityRiskLevel.MEDIUM

    def test_classify_shell_safe(self):
        safe_commands = [
            "ls -la",
            "cat /app/README.md",
            "pytest tests/",
            "python -m build",
            "echo 'Hello world'",
            "pwd",
        ]
        for cmd in safe_commands:
            event = ShellCommandEvent(
                agent_id="agent-01",
                session_id="sess-01",
                command=cmd,
            )
            state = self.classifier.classify(event)
            assert state.security_category == SecurityStateCategory.SHELL_SAFE, f"Failed for {cmd}"
            assert state.risk_level == SecurityRiskLevel.INFO

    def test_classify_network_destinations(self):
        # 1. Sensitive: IMDS / Localhost / Private IPs
        sensitive_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://localhost:8080/admin",
            "http://127.0.0.1:3000/metrics",
            "http://192.168.1.100/config",
            "http://10.0.0.5/api",
        ]
        for url in sensitive_urls:
            event = NetworkRequestEvent(
                agent_id="agent-01",
                session_id="sess-01",
                url=url,
                method="GET",
            )
            state = self.classifier.classify(event)
            assert state.security_category == SecurityStateCategory.NETWORK_SENSITIVE, f"Failed for {url}"
            assert state.risk_level == SecurityRiskLevel.HIGH

        # 2. Trusted
        trusted_urls = [
            "https://api.openai.com/v1/chat/completions",
            "https://api.github.com/repos/org/repo",
            "https://github.com/login",
            "https://pypi.org/simple",
        ]
        for url in trusted_urls:
            event = NetworkRequestEvent(
                agent_id="agent-01",
                session_id="sess-01",
                url=url,
            )
            state = self.classifier.classify(event)
            assert state.security_category == SecurityStateCategory.NETWORK_TRUSTED, f"Failed for {url}"
            assert state.risk_level == SecurityRiskLevel.INFO

        # 3. Unknown external
        unknown_urls = [
            "https://external-service.xyz/webhook",
            "http://untrusted-api.io/data",
        ]
        for url in unknown_urls:
            event = NetworkRequestEvent(
                agent_id="agent-01",
                session_id="sess-01",
                url=url,
            )
            state = self.classifier.classify(event)
            assert state.security_category == SecurityStateCategory.NETWORK_UNKNOWN, f"Failed for {url}"

    def test_classify_filesystem_and_secrets(self):
        # Regular reads / writes / deletes
        ev_read = FilesystemReadEvent(
            agent_id="agent-01",
            session_id="sess-01",
            path="/src/app/main.py",
        )
        assert self.classifier.classify(ev_read).security_category == SecurityStateCategory.FILE_READ

        ev_write = FilesystemWriteEvent(
            agent_id="agent-01",
            session_id="sess-01",
            path="/src/app/main.py",
        )
        assert self.classifier.classify(ev_write).security_category == SecurityStateCategory.FILE_WRITE

        ev_del = FilesystemDeleteEvent(
            agent_id="agent-01",
            session_id="sess-01",
            path="/tmp/cache.bin",
        )
        assert self.classifier.classify(ev_del).security_category == SecurityStateCategory.FILE_DELETE

        # Accessing secret files
        secret_paths = [
            "/app/.env",
            "/home/user/.ssh/id_rsa",
            "/root/.aws/credentials",
            "/etc/shadow",
            "/app/config/credentials.json",
        ]
        for path in secret_paths:
            ev_sec = FilesystemReadEvent(
                agent_id="agent-01",
                session_id="sess-01",
                path=path,
            )
            state = self.classifier.classify(ev_sec)
            assert state.security_category == SecurityStateCategory.SECRET_ACCESS, f"Failed for {path}"
            assert state.risk_level == SecurityRiskLevel.HIGH

    def test_classify_git_operations(self):
        ev_commit = GitOperationEvent(
            agent_id="agent-01",
            session_id="sess-01",
            operation="commit",
        )
        assert self.classifier.classify(ev_commit).security_category == SecurityStateCategory.GIT_COMMIT

        ev_push = GitOperationEvent(
            agent_id="agent-01",
            session_id="sess-01",
            operation="push",
        )
        assert self.classifier.classify(ev_push).security_category == SecurityStateCategory.GIT_PUSH

        ev_read = GitOperationEvent(
            agent_id="agent-01",
            session_id="sess-01",
            operation="status",
        )
        assert self.classifier.classify(ev_read).security_category == SecurityStateCategory.GIT_READ

    def test_classify_process_lifecycle(self):
        ev_proc = ProcessCreationEvent(
            agent_id="agent-01",
            session_id="sess-01",
            command_line="python worker.py",
            pid=1234,
        )
        assert self.classifier.classify(ev_proc).security_category == SecurityStateCategory.PROCESS_CREATE

        ev_term = Event(
            agent_id="agent-01",
            session_id="sess-01",
            event_type="PROCESS_TERMINATION",
            action="KILL",
            target="pid:1234",
        )
        assert self.classifier.classify(ev_term).security_category == SecurityStateCategory.PROCESS_TERMINATE

    def test_classify_credentials_and_secrets(self):
        ev_cred = CredentialAccessEvent(
            agent_id="agent-01",
            session_id="sess-01",
            credential_type="api_key",
            target="STRIPE_API_KEY",
        )
        state = self.classifier.classify(ev_cred)
        assert state.security_category == SecurityStateCategory.CREDENTIAL_ACCESS

    def test_classify_llm_and_tools(self):
        ev_req = LLMRequestEvent(
            agent_id="agent-01",
            session_id="sess-01",
            model="gpt-4o",
            prompt="Refactor this function",
        )
        assert self.classifier.classify(ev_req).security_category == SecurityStateCategory.LLM_REQUEST

        ev_resp = LLMResponseEvent(
            agent_id="agent-01",
            session_id="sess-01",
            model="gpt-4o",
            response="Here is the refactored code",
        )
        assert self.classifier.classify(ev_resp).security_category == SecurityStateCategory.LLM_RESPONSE

        ev_tool = ToolCallEvent(
            agent_id="agent-01",
            session_id="sess-01",
            tool_name="bash",
            arguments={"cmd": "ls"},
        )
        assert self.classifier.classify(ev_tool).security_category == SecurityStateCategory.TOOL_CALL

        ev_tool_res = ToolResultEvent(
            agent_id="agent-01",
            session_id="sess-01",
            tool_name="bash",
            output="file.txt",
        )
        assert self.classifier.classify(ev_tool_res).security_category == SecurityStateCategory.TOOL_RESULT

    def test_classify_agent_communication(self):
        ev_msg = AgentCommunicationEvent(
            agent_id="agent-01",
            session_id="sess-01",
            recipient_agent_id="agent-02",
            message_type="query",
        )
        assert self.classifier.classify(ev_msg).security_category == SecurityStateCategory.AGENT_MESSAGE

        ev_handoff = AgentCommunicationEvent(
            agent_id="agent-01",
            session_id="sess-01",
            recipient_agent_id="agent-02",
            message_type="handoff",
        )
        assert self.classifier.classify(ev_handoff).security_category == SecurityStateCategory.AGENT_HANDOFF

    def test_classify_approval_and_policy(self):
        ev_app = HumanApprovalEvent(
            agent_id="agent-01",
            session_id="sess-01",
            approver="security_team",
            status="APPROVED",
        )
        assert self.classifier.classify(ev_app).security_category == SecurityStateCategory.HUMAN_APPROVAL

        ev_allow = PolicyDecisionEvent(
            agent_id="agent-01",
            session_id="sess-01",
            policy_id="pol-01",
            decision="ALLOW",
        )
        assert self.classifier.classify(ev_allow).security_category == SecurityStateCategory.POLICY_ALLOW

        ev_review = PolicyDecisionEvent(
            agent_id="agent-01",
            session_id="sess-01",
            policy_id="pol-01",
            decision="REVIEW",
        )
        assert self.classifier.classify(ev_review).security_category == SecurityStateCategory.POLICY_REVIEW

        ev_block = PolicyDecisionEvent(
            agent_id="agent-01",
            session_id="sess-01",
            policy_id="pol-01",
            decision="BLOCK",
        )
        state_block = self.classifier.classify(ev_block)
        assert state_block.security_category == SecurityStateCategory.POLICY_BLOCK
        assert state_block.risk_level == SecurityRiskLevel.HIGH

    def test_classify_unknown_fallback(self):
        ev_unknown = Event(
            agent_id="agent-01",
            session_id="sess-01",
            event_type="CUSTOM_EVENT",
            action="CUSTOM_ACTION",
            target="unknown_target",
        )
        state = self.classifier.classify(ev_unknown)
        assert state.security_category == SecurityStateCategory.UNKNOWN


class TestEnrichmentPipeline:
    """Verifies that future semantic classifiers (such as Laya) can enrich states."""

    class MockLayaEnricher(BaseStateEnricher):
        """Simulates an external semantic classifier enricher."""

        @property
        def enricher_name(self) -> str:
            return "laya_semantic_v1"

        def enrich(self, state: SecurityState, event: Event) -> SecurityState:
            # If a SHELL_SAFE command references an environment variable with KEY or SECRET,
            # semantically upgrade to SECRET_ACCESS
            cmd = state.attributes.get("command", "")
            if "KEY" in cmd.upper() or "SECRET" in cmd.upper():
                return state.with_enrichment(
                    security_category=SecurityStateCategory.SECRET_ACCESS,
                    confidence=0.92,
                    classifier_source="laya_semantic_v1",
                    attributes_update={"laya_reason": "command inspects secret variable"},
                )
            return state

    class FailingEnricher(BaseStateEnricher):
        """Simulates a faulty enricher to verify pipeline resilience."""

        @property
        def enricher_name(self) -> str:
            return "broken_enricher"

        def enrich(self, state: SecurityState, event: Event) -> SecurityState:
            raise RuntimeError("Unexpected semantic service outage")

    def test_pipeline_enrichment_flow(self):
        pipeline = SecurityClassificationPipeline()
        pipeline.add_enricher(self.MockLayaEnricher())

        assert pipeline.list_enrichers() == ["laya_semantic_v1"]

        # Safe command that doesn't trigger semantic rule
        ev1 = ShellCommandEvent(
            agent_id="agent-01",
            session_id="sess-01",
            command="echo hello",
        )
        state1 = pipeline.classify(ev1)
        assert state1.security_category == SecurityStateCategory.SHELL_SAFE
        assert state1.classifier_source == "deterministic"

        # Safe command that triggers semantic enrichment
        ev2 = ShellCommandEvent(
            agent_id="agent-01",
            session_id="sess-01",
            command="echo $AWS_SECRET_KEY",
        )
        state2 = pipeline.classify(ev2)
        assert state2.security_category == SecurityStateCategory.SECRET_ACCESS
        assert state2.confidence == 0.92
        assert state2.classifier_source == "laya_semantic_v1"
        assert state2.attributes["laya_reason"] == "command inspects secret variable"

    def test_pipeline_fault_tolerance(self):
        pipeline = SecurityClassificationPipeline()
        pipeline.add_enricher(self.FailingEnricher())

        ev = ShellCommandEvent(
            agent_id="agent-01",
            session_id="sess-01",
            command="ls -la",
        )
        # Should not raise exception, logs warning and returns deterministic state
        state = pipeline.classify(ev)
        assert state.security_category == SecurityStateCategory.SHELL_SAFE

    def test_registry_integration(self):
        registry = SecurityClassifierRegistry()
        pipeline = registry.get_pipeline()
        assert isinstance(pipeline, SecurityClassificationPipeline)

        enricher = self.MockLayaEnricher()
        registry.register_enricher(enricher)
        assert "laya_semantic_v1" in pipeline.list_enrichers()

        # Global classify_event convenience function
        ev = ShellCommandEvent(
            agent_id="agent-01",
            session_id="sess-01",
            command="git status",
        )
        state = classify_event(ev)
        assert state.security_category == SecurityStateCategory.SHELL_SAFE


class TestMarkovStateAdapter:
    """Verifies that MarkovStateAdapter integrates events, SecurityStates, and MarkovModel."""

    def test_adapter_training_and_probabilities(self):
        adapter = MarkovStateAdapter(markov_model=MarkovModel(smoothing=0.0))

        # Trace 1: LLM_REQUEST -> TOOL_CALL -> FILE_READ
        ev_llm = LLMRequestEvent(agent_id="a1", session_id="s1", model="gpt-4o", prompt="Read file")
        ev_tool = ToolCallEvent(agent_id="a1", session_id="s1", tool_name="fs_read", arguments={})
        ev_read = FilesystemReadEvent(agent_id="a1", session_id="s1", path="main.py")

        trace = [ev_llm, ev_tool, ev_read, ev_tool, ev_read]
        adapter.train_events([trace])

        # Verify transition probabilities
        p_tool_llm = adapter.transition_probability("LLM_REQUEST", "TOOL_CALL")
        p_read_tool = adapter.transition_probability("TOOL_CALL", "FILE_READ")
        p_tool_read = adapter.transition_probability("FILE_READ", "TOOL_CALL")

        assert p_tool_llm == 1.0
        assert p_read_tool == 1.0
        assert p_tool_read == 0.5

        # Joint sequence probability
        seq_prob = adapter.sequence_probability([ev_llm, ev_tool, ev_read])
        assert seq_prob == 1.0

    def test_adapter_streaming_observe_event(self):
        adapter = MarkovStateAdapter(markov_model=MarkovModel(smoothing=0.0))

        ev1 = ShellCommandEvent(agent_id="a1", session_id="s1", command="ls")
        ev2 = ShellCommandEvent(agent_id="a1", session_id="s1", command="cat main.py")
        ev3 = ShellCommandEvent(agent_id="a1", session_id="s1", command="echo hello")

        # First observation (no previous)
        state1, prob1 = adapter.observe_event(None, ev1)
        assert state1.security_category == SecurityStateCategory.SHELL_SAFE
        assert prob1 == 1.0

        # Second observation: evaluates P(SHELL_SAFE | SHELL_SAFE) before update (0.0),
        # then increments transition count SHELL_SAFE -> SHELL_SAFE
        state2, prob2 = adapter.observe_event(state1, ev2)
        assert state2.security_category == SecurityStateCategory.SHELL_SAFE
        assert prob2 == 0.0
        assert adapter.transition_probability(state1, state2) == 1.0

        # Third observation: now P(SHELL_SAFE | SHELL_SAFE) is 1.0
        state3, prob3 = adapter.observe_event(state2, ev3)
        assert state3.security_category == SecurityStateCategory.SHELL_SAFE
        assert prob3 == 1.0

    def test_adapter_train_states_directly(self):
        adapter = MarkovStateAdapter(markov_model=MarkovModel(smoothing=0.0))
        ctx = StateContext(agent_id="a1", session_id="s1")

        s1 = SecurityState(security_category=SecurityStateCategory.LLM_REQUEST, context=ctx)
        s2 = SecurityState(security_category=SecurityStateCategory.TOOL_CALL, context=ctx)
        s3 = SecurityState(security_category=SecurityStateCategory.SHELL_SAFE, context=ctx)

        adapter.train_states([[s1, s2, s3]])
        assert adapter.transition_probability(s1, s2) == 1.0
        assert adapter.transition_probability(s2, s3) == 1.0

    def test_adapter_explainability(self):
        adapter = MarkovStateAdapter(markov_model=MarkovModel(smoothing=0.0))
        ctx = StateContext(agent_id="a1", session_id="s1")
        s1 = SecurityState(security_category=SecurityStateCategory.SHELL_SAFE, context=ctx)
        s2 = SecurityState(security_category=SecurityStateCategory.SHELL_NETWORK, context=ctx)

        adapter.train_states([[s1, s2]])
        explanation = adapter.explain(s1, s2)
        assert explanation.prev_state == "SHELL_SAFE"
        assert explanation.curr_state == "SHELL_NETWORK"
        assert explanation.probability == 1.0


class TestSPRTIntegration:
    """Verifies that SecurityState works seamlessly with the existing SPRTEngine."""

    def test_sprt_fit_and_observe_with_security_states(self):
        # 1. Setup Markov model and SPRT hypothesis
        markov_model = MarkovModel(smoothing=1e-3)
        hypothesis = Hypothesis(
            alpha=0.05,
            beta=0.05,
            vocabulary_size=28,
            alternative_model=UniformAlternativeModel(vocabulary_size=28),
        )
        sprt_engine = SPRTEngine(markov_model=markov_model, hypothesis=hypothesis)

        ctx = StateContext(agent_id="agent-01", session_id="sess-sprt-01")

        s_llm = SecurityState(security_category=SecurityStateCategory.LLM_REQUEST, context=ctx)
        s_tool = SecurityState(security_category=SecurityStateCategory.TOOL_CALL, context=ctx)
        s_read = SecurityState(security_category=SecurityStateCategory.FILE_READ, context=ctx)

        # 2. Fit SPRTEngine with SecurityState sequences
        normal_trace = [s_llm, s_tool, s_read] * 10
        sprt_engine.fit([normal_trace])

        # 3. Stream normal observations
        res1 = sprt_engine.observe(s_llm)
        assert res1.decision in ("NORMAL", "PENDING")

        res2 = sprt_engine.observe(s_tool)
        assert res2.decision in ("NORMAL", "PENDING")

        res3 = sprt_engine.observe(s_read)
        assert res3.decision in ("NORMAL", "PENDING")
