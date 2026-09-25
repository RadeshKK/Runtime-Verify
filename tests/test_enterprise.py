"""
Integration and Unit Tests for Enterprise Architecture Subsystem (Phase 18).
Validates multi-tenant isolation, RBAC, conceptual environments, OIDC/Keycloak auth,
API keys, S2S auth, hierarchical PolicySets, dual-control approvals, and tamper-evident audit chaining.
"""

from datetime import datetime, timezone
import pytest

from runtimeverify.enterprise.approval import (
    EnterpriseApprovalManager,
)
from runtimeverify.enterprise.audit import EnterpriseAuditManager
from runtimeverify.enterprise.auth import (
    EnterpriseApiKeyManager,
    GenericOIDCClaimsExtractor,
    KeycloakClaimsExtractor,
    ServiceToServiceAuth,
    TokenValidationError,
    TokenValidator,
)
from runtimeverify.enterprise.context import (
    EnterpriseContext,
    enterprise_scope,
    get_current_context,
)
from runtimeverify.enterprise.isolation import (
    PartitionedStore,
    TenantIsolationEngine,
    TenantIsolationViolationError,
)
from runtimeverify.enterprise.models import (
    ActorType,
    ApprovalStatus,
    AuditOwnership,
    EnforcementMode,
    Environment,
    Organization,
    PolicySet,
    PolicySetScope,
    Project,
    Tenant,
    TenantStatus,
)
from runtimeverify.enterprise.policyset import PolicySetManager
from runtimeverify.enterprise.rbac import (
    AccessControlEvaluator,
    EnterprisePermission,
    EnterpriseRole,
    Resource,
    Subject,
)


def test_enterprise_models_and_slug_validation():
    """Tenant, Organization, and Project enforce valid slug syntax and hierarchy."""
    tenant = Tenant(name="Acme Corporation", slug="acme-corp", status=TenantStatus.ACTIVE)
    assert tenant.slug == "acme-corp"
    assert tenant.id.startswith("tenant-")

    with pytest.raises(ValueError, match="Slug must contain only lowercase alphanumeric"):
        Tenant(name="Bad Slug", slug="Acme_Corp!")

    org = Organization(tenant_id=tenant.id, name="Security Operations", slug="secops")
    assert org.tenant_id == tenant.id
    assert org.slug == "secops"

    proj = Project(
        tenant_id=tenant.id,
        organization_id=org.id,
        name="Autonomous Coder",
        slug="auto-coder",
        environments_enabled=[Environment.DEVELOPMENT, Environment.PRODUCTION],
    )
    assert proj.tenant_id == tenant.id
    assert proj.organization_id == org.id

    # Test environment properties
    assert Environment.PRODUCTION.is_production is True
    assert Environment.PRODUCTION.requires_dual_control is True
    assert Environment.DEVELOPMENT.allows_permissive_override is True


def test_enterprise_context_and_scope_propagation():
    """EnterpriseContext propagates ambiently via contextvars and safely restores previous scope."""
    assert get_current_context() is None

    with enterprise_scope(
        tenant_id="tenant-alpha",
        organization_id="org-eng",
        project_id="proj-coder",
        environment=Environment.PRODUCTION,
        actor_id="user-123",
        actor_type=ActorType.USER,
        roles=["security_engineer"],
    ) as ctx:
        current = get_current_context()
        assert current is not None
        assert current == ctx
        assert current.tenant_id == "tenant-alpha"
        assert current.environment == Environment.PRODUCTION
        assert current.has_role("security_engineer") is True
        assert current.has_role("developer") is False

        # Nested scope
        with enterprise_scope(
            tenant_id="tenant-beta",
            environment=Environment.DEVELOPMENT,
            actor_id="dev-456",
        ) as inner_ctx:
            assert get_current_context() == inner_ctx
            assert get_current_context().tenant_id == "tenant-beta"
            assert get_current_context().environment == Environment.DEVELOPMENT

        # Restored outer scope
        assert get_current_context().tenant_id == "tenant-alpha"

    # Restored root
    assert get_current_context() is None


def test_enterprise_rbac_permissions_and_wildcards():
    """RBAC roles resolve standard permissions and super_admin inherits wildcard."""
    admin_sub = Subject(id="admin-01", tenant_id="t1", roles=[EnterpriseRole.SUPER_ADMIN.value])
    perms = admin_sub.resolve_permissions()
    assert EnterprisePermission.ALL.value in perms

    dev_sub = Subject(id="dev-01", tenant_id="t1", roles=[EnterpriseRole.DEVELOPER.value])
    dev_perms = dev_sub.resolve_permissions()
    assert EnterprisePermission.PROJECT_READ.value in dev_perms
    assert EnterprisePermission.POLICY_WRITE.value not in dev_perms

    sec_sub = Subject(id="sec-01", tenant_id="t1", roles=[EnterpriseRole.SECURITY_ENGINEER.value])
    sec_perms = sec_sub.resolve_permissions()
    assert EnterprisePermission.POLICY_WRITE.value in sec_perms
    assert EnterprisePermission.APPROVAL_APPROVE.value in sec_perms


def test_access_control_evaluator_tenant_isolation():
    """Cross-tenant access attempts are strictly rejected by the AccessControlEvaluator."""
    subject = Subject(
        id="user-01",
        tenant_id="tenant-acme",
        roles=[EnterpriseRole.SECURITY_ENGINEER.value],
    )
    foreign_resource = Resource(
        type="policy",
        id="pol-999",
        tenant_id="tenant-globex",
        environment=Environment.DEVELOPMENT,
    )

    decision = AccessControlEvaluator.evaluate(
        subject=subject,
        action=EnterprisePermission.POLICY_READ.value,
        resource=foreign_resource,
    )
    assert decision.granted is False
    assert "Tenant isolation violation" in decision.reason

    # SuperAdmin is permitted cross-tenant access for platform operations
    super_admin = Subject(
        id="root-01",
        tenant_id="tenant-platform",
        roles=[EnterpriseRole.SUPER_ADMIN.value],
    )
    sa_decision = AccessControlEvaluator.evaluate(
        subject=super_admin,
        action=EnterprisePermission.POLICY_READ.value,
        resource=foreign_resource,
    )
    assert sa_decision.granted is True


def test_access_control_evaluator_production_guardrails():
    """Developers cannot write policies or approve actions in PRODUCTION."""
    dev = Subject(
        id="dev-01",
        tenant_id="tenant-acme",
        roles=[EnterpriseRole.DEVELOPER.value],
        custom_permissions={EnterprisePermission.POLICY_WRITE.value},  # attempts custom escalation
    )
    prod_policy_res = Resource(
        type="policy",
        tenant_id="tenant-acme",
        environment=Environment.PRODUCTION,
    )

    decision = AccessControlEvaluator.evaluate(
        subject=dev,
        action=EnterprisePermission.POLICY_WRITE.value,
        resource=prod_policy_res,
        target_env=Environment.PRODUCTION,
    )
    assert decision.granted is False
    assert "Developers cannot modify policies or approve actions in PRODUCTION" in decision.reason

    # Security Engineer is allowed in production
    sec_eng = Subject(
        id="sec-01",
        tenant_id="tenant-acme",
        roles=[EnterpriseRole.SECURITY_ENGINEER.value],
    )
    sec_decision = AccessControlEvaluator.evaluate(
        subject=sec_eng,
        action=EnterprisePermission.POLICY_WRITE.value,
        resource=prod_policy_res,
        target_env=Environment.PRODUCTION,
    )
    assert sec_decision.granted is True


def test_access_control_evaluator_segregation_of_duties():
    """Users/Agents cannot self-approve their own escalation requests."""
    sec_eng = Subject(
        id="user-requester-01",
        tenant_id="tenant-acme",
        roles=[EnterpriseRole.SECURITY_ENGINEER.value],
    )
    approval_res = Resource(
        type="approval",
        id="appr-123",
        tenant_id="tenant-acme",
        owner_id="user-requester-01",  # Self
        environment=Environment.PRODUCTION,
    )

    decision = AccessControlEvaluator.evaluate(
        subject=sec_eng,
        action=EnterprisePermission.APPROVAL_APPROVE.value,
        resource=approval_res,
    )
    assert decision.granted is False
    assert "Segregation of Duties (SOD) violation: Self-approval is strictly prohibited" in decision.reason


def test_keycloak_claims_extractor():
    """KeycloakClaimsExtractor maps realm_access and resource_access roles and tenant attributes."""
    keycloak_jwt = {
        "iss": "https://auth.enterprise.com/realms/rv-realm",
        "sub": "kc-user-789",
        "preferred_username": "secops_lead",
        "email": "secops@enterprise.com",
        "aud": ["runtimeverify-api"],
        "realm_access": {"roles": ["security_engineer", "default-roles-rv"]},
        "resource_access": {"runtimeverify-api": {"roles": ["api_admin"]}},
        "attributes": {"tenant_id": ["tenant-enterprise-01"]},
        "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
    }

    extractor = KeycloakClaimsExtractor(client_id="runtimeverify-api")
    claims = extractor.extract_claims(keycloak_jwt)

    assert claims.subject == "kc-user-789"
    assert claims.username == "secops_lead"
    assert claims.tenant_id == "tenant-enterprise-01"
    assert "security_engineer" in claims.roles
    assert "api_admin" in claims.roles


def test_generic_oidc_claims_extractor():
    """GenericOIDCClaimsExtractor extracts standard OIDC claims and groups."""
    payload = {
        "iss": "https://okta.company.com/oauth2/default",
        "sub": "okta-usr-456",
        "preferred_username": "dev_engineer",
        "roles": ["developer"],
        "tenant_id": "tenant-corp",
        "exp": int(datetime.now(timezone.utc).timestamp()) + 1800,
    }

    extractor = GenericOIDCClaimsExtractor()
    claims = extractor.extract_claims(payload)
    assert claims.subject == "okta-usr-456"
    assert claims.tenant_id == "tenant-corp"
    assert "developer" in claims.roles


def test_token_validator_temporal_and_issuer_checks():
    """TokenValidator rejects expired tokens and issuer mismatches."""
    validator = TokenValidator(issuer="https://trusted-idp.com", audience="rv-service")

    # Expired payload
    expired_token = (
        "eyJhbGciOiJub25lIn0."
        + "eyJpc3MiOiAiaHR0cHM6Ly90cnVzdGVkLWlkcC5jb20iLCAiYXVkIjogInJ2LXNlcnZpY2UiLCAic3ViIjogInU5OSIsICJleHAiOiAxMDAwMDAwfQ."
    )
    with pytest.raises(TokenValidationError, match="Token has expired"):
        validator.validate_token(expired_token)

    # Issuer mismatch
    import base64
    import json

    wrong_iss_payload = {
        "iss": "https://fake-idp.com",
        "aud": "rv-service",
        "sub": "u99",
        "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
    }
    encoded_payload = base64.urlsafe_b64encode(json.dumps(wrong_iss_payload).encode("utf-8")).decode("utf-8")
    wrong_iss_token = f"eyJhbGciOiJub25lIn0.{encoded_payload}."
    with pytest.raises(TokenValidationError, match="Issuer mismatch"):
        validator.validate_token(wrong_iss_token)


def test_enterprise_api_key_manager():
    """EnterpriseApiKeyManager generates hashed keys, verifies valid keys, and rejects revoked ones."""
    manager = EnterpriseApiKeyManager()

    # Generate live key (production)
    raw_key, record = manager.generate_api_key(
        tenant_id="tenant-prod-corp",
        name="CI Deployment Key",
        environment=Environment.PRODUCTION,
        roles=["security_engineer"],
    )
    assert raw_key.startswith("rv_live_")
    assert record.environment == Environment.PRODUCTION
    assert raw_key != record.hashed_secret  # Secret is hashed, never plaintext

    # Verify key
    verified = manager.verify_api_key(raw_key)
    assert verified is not None
    assert verified.tenant_id == "tenant-prod-corp"
    assert verified.environment == Environment.PRODUCTION

    # Environment mismatch rejection
    tampered_test_key = raw_key.replace("rv_live_", "rv_test_")
    assert manager.verify_api_key(tampered_test_key) is None

    # Revoke key
    assert manager.revoke_key(record.key_id) is True
    assert manager.verify_api_key(raw_key) is None


def test_service_to_service_auth():
    """ServiceToServiceAuth generates signed machine assertions and verifies authenticity."""
    s2s = ServiceToServiceAuth(shared_secret="super-secure-shared-key-32-chars", expected_service_audience="rv-mesh")

    token = s2s.create_service_token(service_name="agent-daemon-01", tenant_id="tenant-s2s-123", ttl_seconds=60)
    subject = s2s.verify_service_token(token)

    assert subject is not None
    assert subject.id == "service:agent-daemon-01"
    assert subject.tenant_id == "tenant-s2s-123"
    assert subject.type == ActorType.SERVICE

    # Tampered token
    tampered = token[:-4] + "abcd"
    assert s2s.verify_service_token(tampered) is None


def test_tenant_isolation_engine_and_partitioned_store():
    """TenantIsolationEngine prevents cross-tenant access and PartitionedStore isolates tenant data."""
    store = PartitionedStore[dict]()

    # Write to Tenant A dev
    store.put("tenant-A", Environment.DEVELOPMENT, "item-1", {"data": "A-dev"})
    # Write to Tenant B dev
    store.put("tenant-B", Environment.DEVELOPMENT, "item-1", {"data": "B-dev"})

    assert store.get("tenant-A", Environment.DEVELOPMENT, "item-1")["data"] == "A-dev"
    assert store.get("tenant-B", Environment.DEVELOPMENT, "item-1")["data"] == "B-dev"

    # Context enforcement
    ctx_a = EnterpriseContext(tenant_id="tenant-A", environment=Environment.DEVELOPMENT)
    TenantIsolationEngine.enforce_access(ctx_a, "tenant-A")

    with pytest.raises(TenantIsolationViolationError, match="Tenant isolation violation"):
        TenantIsolationEngine.enforce_access(ctx_a, "tenant-B")

    with pytest.raises(TenantIsolationViolationError, match="Environment boundary violation"):
        TenantIsolationEngine.enforce_environment(ctx_a, Environment.PRODUCTION)


def test_hierarchical_policyset_resolution():
    """PolicySetManager resolves policies hierarchically and enforces immutable tenant guardrails."""
    ps_mgr = PolicySetManager()

    # 1. Tenant Immutable Guardrail (e.g. No destructive shell)
    guardrail = PolicySet(
        tenant_id="tenant-xyz",
        name="Global Guardrails",
        scope=PolicySetScope.TENANT,
        immutable=True,
        enforcement_mode=EnforcementMode.ENFORCE,
        policies=[{"rule_id": "guardrail-01", "action": "BLOCK", "pattern": "rm -rf /"}],
    )
    ps_mgr.register_policyset(guardrail)

    # 2. Org Policy (Engineering)
    org_policy = PolicySet(
        tenant_id="tenant-xyz",
        organization_id="org-eng",
        name="Engineering Standard Policy",
        scope=PolicySetScope.ORGANIZATION,
        policies=[{"rule_id": "org-01", "action": "ALLOW", "tool": "git"}],
    )
    ps_mgr.register_policyset(org_policy)

    # 3. Project Policy (Autonomous Coder)
    proj_policy = PolicySet(
        tenant_id="tenant-xyz",
        organization_id="org-eng",
        project_id="proj-coder",
        name="Coder Project Policy",
        scope=PolicySetScope.PROJECT,
        policies=[{"rule_id": "proj-01", "action": "REVIEW", "tool": "docker"}],
    )
    ps_mgr.register_policyset(proj_policy)

    # Resolve for project coder
    result = ps_mgr.resolve_effective_policies(
        tenant_id="tenant-xyz",
        organization_id="org-eng",
        project_id="proj-coder",
        environment=Environment.PRODUCTION,
    )

    assert result.immutable_guardrails_applied is True
    assert len(result.resolved_policies) == 3
    # First policy must be the immutable tenant guardrail
    assert result.resolved_policies[0]["rule_id"] == "guardrail-01"
    assert result.resolved_policies[0]["_immutable"] is True

    # Attempting to delete immutable guardrail must fail
    with pytest.raises(ValueError, match="Cannot delete immutable PolicySet"):
        ps_mgr.delete_policyset(guardrail.id)


def test_enterprise_audit_manager_and_tamper_detection():
    """EnterpriseAuditManager constructs valid cryptographic hash chains and detects tampering."""
    audit_mgr = EnterpriseAuditManager()

    # Append 3 audit records
    r1 = audit_mgr.record_entry(
        tenant_id="tenant-audit-test",
        organization_id="org-1",
        project_id="proj-1",
        environment=Environment.PRODUCTION,
        actor_id="agent-01",
        action="shell_exec",
        verdict="ALLOW",
        event_id="ev-001",
    )
    r2 = audit_mgr.record_entry(
        tenant_id="tenant-audit-test",
        organization_id="org-1",
        project_id="proj-1",
        environment=Environment.PRODUCTION,
        actor_id="agent-01",
        action="read_file",
        verdict="ALLOW",
        event_id="ev-002",
    )
    r3 = audit_mgr.record_entry(
        tenant_id="tenant-audit-test",
        organization_id="org-1",
        project_id="proj-1",
        environment=Environment.PRODUCTION,
        actor_id="agent-01",
        action="delete_db",
        verdict="BLOCK",
        event_id="ev-003",
    )

    assert r2.prev_hash == r1.hash
    assert r3.prev_hash == r2.hash

    # Verify untampered chain
    is_valid, reason = audit_mgr.verify_chain("tenant-audit-test", Environment.PRODUCTION)
    assert is_valid is True
    assert reason is None

    # Simulate tampering on record 2
    tampered_r2 = AuditOwnership(
        id=r2.id,
        tenant_id=r2.tenant_id,
        organization_id=r2.organization_id,
        project_id=r2.project_id,
        environment=r2.environment,
        session_id=r2.session_id,
        event_id=r2.event_id,
        decision_id=r2.decision_id,
        actor_id=r2.actor_id,
        actor_type=r2.actor_type,
        action=r2.action,
        verdict="ALLOW",
        hash="tampered_hash_1234567890abcdef",  # altered
        prev_hash=r2.prev_hash,
        timestamp=r2.timestamp,
    )
    # Inject tampered record into chain
    audit_mgr._chains[f"tenant-audit-test:{Environment.PRODUCTION.value}"][1] = tampered_r2

    # Verification must fail
    is_valid, reason = audit_mgr.verify_chain("tenant-audit-test", Environment.PRODUCTION)
    assert is_valid is False
    assert "tampering detected" in reason.lower() or "broken" in reason.lower()


def test_enterprise_approval_manager_dual_control():
    """EnterpriseApprovalManager enforces dual-control (2 approvers in prod) and SOD self-approval."""
    mgr = EnterpriseApprovalManager()

    # Create approval request in PRODUCTION (requires 2 approvers by default)
    req = mgr.create_request(
        tenant_id="tenant-appr-test",
        organization_id="org-sec",
        project_id="proj-core",
        environment=Environment.PRODUCTION,
        session_id="sess-99",
        agent_id="agent-requester-01",
        action_type="network_egress",
        action_target="192.168.1.100:443",
        risk_level="HIGH",
    )
    assert req.status == ApprovalStatus.PENDING
    assert req.required_approvals == 2

    # Requester cannot self-approve (SOD)
    with pytest.raises(PermissionError, match="Requester cannot approve their own action"):
        mgr.approve(req.id, approver_id="agent-requester-01", approver_roles=["security_engineer"])

    # First approver signs
    res1 = mgr.approve(req.id, approver_id="sec-eng-01", approver_roles=["security_engineer"])
    assert res1.status == ApprovalStatus.PENDING
    assert res1.remaining_approvals == 1
    assert "sec-eng-01" in res1.approved_by

    # Same approver cannot sign twice
    with pytest.raises(ValueError, match="already approved this request"):
        mgr.approve(req.id, approver_id="sec-eng-01", approver_roles=["security_engineer"])

    # Second approver signs (satisfies dual control threshold)
    res2 = mgr.approve(req.id, approver_id="sec-eng-02", approver_roles=["security_engineer"])
    assert res2.status == ApprovalStatus.APPROVED
    assert res2.remaining_approvals == 0

    # Rejected request terminates immediately
    req_to_reject = mgr.create_request(
        tenant_id="tenant-appr-test",
        organization_id="org-sec",
        project_id="proj-core",
        environment=Environment.PRODUCTION,
        session_id="sess-100",
        agent_id="agent-02",
        action_type="destructive_shell",
        action_target="drop database",
    )
    res_rej = mgr.reject(req_to_reject.id, rejector_id="sec-lead-01", reason="Unsafe in production")
    assert res_rej.status == ApprovalStatus.REJECTED
    assert "Unsafe in production" in res_rej.message


def test_api_auth_context_to_enterprise_context_bridge():
    """AuthContext from API layer converts cleanly into an EnterpriseContext."""
    from runtimeverify.api.auth import AuthContext

    auth_ctx = AuthContext(
        user_id="usr-cloud-01",
        authenticated=True,
        roles=["security_engineer"],
        permissions={"policy:write", "approval:approve"},
        tenant_id="tenant-corp-99",
        organization_id="org-sec",
        environment="production",
    )

    ent_ctx = auth_ctx.to_enterprise_context()
    assert ent_ctx.tenant_id == "tenant-corp-99"
    assert ent_ctx.organization_id == "org-sec"
    assert ent_ctx.environment == Environment.PRODUCTION
    assert ent_ctx.actor_id == "usr-cloud-01"
    assert ent_ctx.has_role("security_engineer") is True
    assert ent_ctx.has_permission("policy:write") is True
