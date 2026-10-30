"""strongemail — 평판과 포털 수신 기준을 지키는 이메일 발송 코어."""

from .blocklist import AppealContext, IncidentLog, build_appeal, check_dnsbls
from .compliance import SenderIdentity, lint_message
from .dns_audit import audit_domain
from .domain_setup import SenderDomainRegistry, generate_dkim_key, setup_plan
from .findings import Finding, Severity
from .providers import PROVIDERS, provider_for
from .reputation import BounceKind, ReputationMonitor, Store, Thresholds, WarmupPlan, classify_smtp_response
from .sender import Category, Consent, Mailer, MailerConfig, OutgoingEmail, SMTPTransport, Status

__all__ = [
    "AppealContext", "IncidentLog", "build_appeal", "check_dnsbls",
    "SenderDomainRegistry", "generate_dkim_key", "setup_plan",
    "SenderIdentity", "lint_message", "audit_domain", "Finding", "Severity", "PROVIDERS", "provider_for",
    "BounceKind", "ReputationMonitor", "Store", "Thresholds", "WarmupPlan", "classify_smtp_response",
    "Category", "Consent", "Mailer", "MailerConfig", "OutgoingEmail", "SMTPTransport", "Status",
]
