"""Seed the control_fixes table with common K8s security fix templates."""
import logging
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.control_fix import ControlFix

logger = logging.getLogger(__name__)

# Workload patch: Deployment/StatefulSet/DaemonSet/ReplicaSet
_WL_KINDS = ["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"]
# All container-bearing kinds including Pod
_ALL_KINDS = _WL_KINDS + ["Pod"]

def _workload_security_context_patch(field: str, value: str) -> str:
    """Generate a strategic merge patch for a container securityContext field."""
    return f"""apiVersion: apps/v1
kind: {{{{resource_kind}}}}
metadata:
  name: {{{{resource_name}}}}
  namespace: {{{{namespace}}}}
spec:
  template:
    spec:
      containers:
      - name: "*"
        securityContext:
          {field}: {value}
"""

def _workload_resource_patch(section: str, cpu: str, memory: str) -> str:
    """Generate a patch for resource requests/limits."""
    return f"""apiVersion: apps/v1
kind: {{{{resource_kind}}}}
metadata:
  name: {{{{resource_name}}}}
  namespace: {{{{namespace}}}}
spec:
  template:
    spec:
      containers:
      - name: "*"
        resources:
          {section}:
            cpu: "{cpu}"
            memory: "{memory}"
"""

def _workload_probe_patch(probe_type: str) -> str:
    return f"""apiVersion: apps/v1
kind: {{{{resource_kind}}}}
metadata:
  name: {{{{resource_name}}}}
  namespace: {{{{namespace}}}}
spec:
  template:
    spec:
      containers:
      - name: "*"
        {probe_type}:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 15
          timeoutSeconds: 3
          failureThreshold: 3
"""


SEED_DATA = [
    # ── Trivy KSV controls ──────────────────────────────────────────────
    {
        "control_id": "KSV-0001",
        "title": "Process can elevate its own privileges",
        "scanner": "trivy",
        "description": "Container should not allow privilege escalation",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": _workload_security_context_patch("allowPrivilegeEscalation", "false"),
        "notes": "Sets allowPrivilegeEscalation: false on all containers. Safe for most workloads.",
    },
    {
        "control_id": "KSV-0003",
        "title": "Default capabilities not dropped",
        "scanner": "trivy",
        "description": "Containers should drop ALL capabilities and add only those required",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": """apiVersion: apps/v1
kind: {{resource_kind}}
metadata:
  name: {{resource_name}}
  namespace: {{namespace}}
spec:
  template:
    spec:
      containers:
      - name: "*"
        securityContext:
          capabilities:
            drop:
              - ALL
""",
        "notes": "Drops ALL Linux capabilities. If your app needs specific capabilities (e.g., NET_BIND_SERVICE for port < 1024), add them back under 'add:'.",
    },
    {
        "control_id": "KSV-0009",
        "title": "Access to host network",
        "scanner": "trivy",
        "description": "Pod should not have access to the host network",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "medium",
        "patch_template": """apiVersion: apps/v1
kind: {{resource_kind}}
metadata:
  name: {{resource_name}}
  namespace: {{namespace}}
spec:
  template:
    spec:
      hostNetwork: false
""",
        "notes": "Disables host network access. WARNING: If the workload needs host networking (e.g., CNI plugins, ingress controllers), this will break it.",
    },
    {
        "control_id": "KSV-0010",
        "title": "Access to host PID namespace",
        "scanner": "trivy",
        "description": "Pod should not share the host PID namespace",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": """apiVersion: apps/v1
kind: {{resource_kind}}
metadata:
  name: {{resource_name}}
  namespace: {{namespace}}
spec:
  template:
    spec:
      hostPID: false
""",
        "notes": "Disables host PID sharing. Safe for most workloads.",
    },
    {
        "control_id": "KSV-0012",
        "title": "Runs as root",
        "scanner": "trivy",
        "description": "Container should run as non-root user",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "medium",
        "patch_template": _workload_security_context_patch("runAsNonRoot", "true"),
        "notes": "Forces containers to run as non-root. WARNING: Some images (nginx, redis default) require root. You may need to also set runAsUser: 1000.",
    },
    {
        "control_id": "KSV-0014",
        "title": "Root file system is not read-only",
        "scanner": "trivy",
        "description": "Container root filesystem should be read-only",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "medium",
        "patch_template": _workload_security_context_patch("readOnlyRootFilesystem", "true"),
        "notes": "Makes root filesystem read-only. Apps that write to /tmp or /var need emptyDir volume mounts for those paths.",
    },
    {
        "control_id": "KSV-0015",
        "title": "CPU limit not set",
        "scanner": "trivy",
        "description": "Container should have CPU limits",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": _workload_resource_patch("limits", "500m", "256Mi"),
        "notes": "Sets CPU limit to 500m (0.5 core). Adjust based on your workload's actual usage. Check metrics first with: kubectl top pods -n {{namespace}}",
    },
    {
        "control_id": "KSV-0016",
        "title": "Memory limit not set",
        "scanner": "trivy",
        "description": "Container should have memory limits",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": _workload_resource_patch("limits", "500m", "256Mi"),
        "notes": "Sets memory limit to 256Mi. Adjust based on your workload. Too low = OOMKilled. Check current usage: kubectl top pods -n {{namespace}}",
    },
    {
        "control_id": "KSV-0017",
        "title": "Privileged container",
        "scanner": "trivy",
        "description": "Container should not run in privileged mode",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": _workload_security_context_patch("privileged", "false"),
        "notes": "Disables privileged mode. WARNING: Some system containers (CNI, storage drivers) legitimately need privileged. Check if your workload actually requires it.",
    },
    {
        "control_id": "KSV-0018",
        "title": "Memory request not set",
        "scanner": "trivy",
        "description": "Container should have memory requests for scheduling",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": _workload_resource_patch("requests", "100m", "128Mi"),
        "notes": "Sets memory request to 128Mi. This helps the scheduler place pods. Set to ~50-75% of your limit.",
    },
    {
        "control_id": "KSV-0020",
        "title": "Runs with low user ID",
        "scanner": "trivy",
        "description": "Container should not run with a UID below 10000",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": """apiVersion: apps/v1
kind: {{resource_kind}}
metadata:
  name: {{resource_name}}
  namespace: {{namespace}}
spec:
  template:
    spec:
      containers:
      - name: "*"
        securityContext:
          runAsUser: 10000
          runAsNonRoot: true
""",
        "notes": "Sets UID to 10000. Make sure the container image supports running as this user.",
    },
    {
        "control_id": "KSV-0021",
        "title": "Runs with low group ID",
        "scanner": "trivy",
        "description": "Container should not run with a GID below 10000",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": """apiVersion: apps/v1
kind: {{resource_kind}}
metadata:
  name: {{resource_name}}
  namespace: {{namespace}}
spec:
  template:
    spec:
      containers:
      - name: "*"
        securityContext:
          runAsGroup: 10000
""",
        "notes": "Sets GID to 10000.",
    },
    {
        "control_id": "KSV-0030",
        "title": "Seccomp profile is not set",
        "scanner": "trivy",
        "description": "Container should use RuntimeDefault or Localhost seccomp profile",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": """apiVersion: apps/v1
kind: {{resource_kind}}
metadata:
  name: {{resource_name}}
  namespace: {{namespace}}
spec:
  template:
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault
""",
        "notes": "Sets RuntimeDefault seccomp profile at pod level. This restricts dangerous syscalls and is safe for most workloads.",
    },
    {
        "control_id": "KSV-0036",
        "title": "Readiness probe not configured",
        "scanner": "trivy",
        "description": "Container should have a readiness probe for health checking",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": _workload_probe_patch("readinessProbe"),
        "notes": "Adds a basic HTTP readiness probe on /healthz:8080. Adjust the path and port to match your application's health endpoint.",
    },
    {
        "control_id": "KSV-0037",
        "title": "Liveness probe not configured",
        "scanner": "trivy",
        "description": "Container should have a liveness probe for restart detection",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": _workload_probe_patch("livenessProbe"),
        "notes": "Adds a basic HTTP liveness probe. Adjust path/port for your app. Too aggressive settings can cause unnecessary restarts.",
    },
    {
        "control_id": "KSV-0038",
        "title": "CPU request not set",
        "scanner": "trivy",
        "description": "Container should have CPU requests for scheduling",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": _workload_resource_patch("requests", "100m", "128Mi"),
        "notes": "Sets CPU request to 100m (0.1 core). Adjust based on workload usage.",
    },
    {
        "control_id": "KSV-0106",
        "title": "Container running with no SecurityContext",
        "scanner": "trivy",
        "description": "Container should have an explicit security context defined",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": """apiVersion: apps/v1
kind: {{resource_kind}}
metadata:
  name: {{resource_name}}
  namespace: {{namespace}}
spec:
  template:
    spec:
      containers:
      - name: "*"
        securityContext:
          runAsNonRoot: true
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL
          seccompProfile:
            type: RuntimeDefault
""",
        "notes": "Adds a comprehensive security context. This is the recommended baseline. You may need to relax readOnlyRootFilesystem if the app writes to disk.",
    },
    {
        "control_id": "KSV-0118",
        "title": "Default security context configured",
        "scanner": "trivy",
        "description": "Relying on default security context exposes vulnerabilities",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": """apiVersion: apps/v1
kind: {{resource_kind}}
metadata:
  name: {{resource_name}}
  namespace: {{namespace}}
spec:
  template:
    spec:
      containers:
      - name: "*"
        securityContext:
          runAsNonRoot: true
          allowPrivilegeEscalation: false
          capabilities:
            drop:
              - ALL
""",
        "notes": "Explicitly sets security context instead of relying on defaults.",
    },
    {
        "control_id": "KSV-0104",
        "title": "Seccomp profile not set on container level",
        "scanner": "trivy",
        "description": "Container should have seccomp profile set",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": """apiVersion: apps/v1
kind: {{resource_kind}}
metadata:
  name: {{resource_name}}
  namespace: {{namespace}}
spec:
  template:
    spec:
      containers:
      - name: "*"
        securityContext:
          seccompProfile:
            type: RuntimeDefault
""",
        "notes": "Sets seccomp at container level. RuntimeDefault is safe for most workloads.",
    },
    {
        "control_id": "KSV-0125",
        "title": "Container without AppArmor profile",
        "scanner": "trivy",
        "description": "Container should have AppArmor profile configured",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": """apiVersion: apps/v1
kind: {{resource_kind}}
metadata:
  name: {{resource_name}}
  namespace: {{namespace}}
  annotations:
    container.apparmor.security.beta.kubernetes.io/*: runtime/default
spec:
  template:
    metadata:
      annotations:
        container.apparmor.security.beta.kubernetes.io/*: runtime/default
""",
        "notes": "Sets AppArmor to runtime/default. Requires AppArmor to be enabled on the node OS.",
    },

    # ── Kubescape C controls ────────────────────────────────────────────
    {
        "control_id": "C-0004",
        "title": "Resources memory limit and target",
        "scanner": "kubescape",
        "description": "Containers should have memory limits configured",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": _workload_resource_patch("limits", "500m", "256Mi"),
        "notes": "Adds memory limits. Check current usage first: kubectl top pods -n {{namespace}}",
    },
    {
        "control_id": "C-0009",
        "title": "Resource CPU limit and request",
        "scanner": "kubescape",
        "description": "Containers should have CPU limits configured",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": _workload_resource_patch("limits", "500m", "256Mi"),
        "notes": "Adds CPU limits. Adjust based on workload metrics.",
    },
    {
        "control_id": "C-0013",
        "title": "Non-root containers",
        "scanner": "kubescape",
        "description": "Containers should run as non-root",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "medium",
        "patch_template": _workload_security_context_patch("runAsNonRoot", "true"),
        "notes": "Forces non-root. Some images need a specific runAsUser to work correctly.",
    },
    {
        "control_id": "C-0016",
        "title": "Allow privilege escalation",
        "scanner": "kubescape",
        "description": "Containers should not allow privilege escalation",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": _workload_security_context_patch("allowPrivilegeEscalation", "false"),
        "notes": "Safe for most workloads.",
    },
    {
        "control_id": "C-0017",
        "title": "Immutable container filesystem",
        "scanner": "kubescape",
        "description": "Container filesystem should be read-only",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "medium",
        "patch_template": _workload_security_context_patch("readOnlyRootFilesystem", "true"),
        "notes": "Mount emptyDir volumes for paths the app writes to (e.g., /tmp, /var/cache).",
    },
    {
        "control_id": "C-0018",
        "title": "Configured readiness probe",
        "scanner": "kubescape",
        "description": "Containers should have readiness probes",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": _workload_probe_patch("readinessProbe"),
        "notes": "Adjust path and port for your application.",
    },
    {
        "control_id": "C-0034",
        "title": "Automatic mapping of service account",
        "scanner": "kubescape",
        "description": "Pods should not auto-mount service account tokens unless needed",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": """apiVersion: apps/v1
kind: {{resource_kind}}
metadata:
  name: {{resource_name}}
  namespace: {{namespace}}
spec:
  template:
    spec:
      automountServiceAccountToken: false
""",
        "notes": "Disables auto-mounting the SA token. WARNING: If your app calls the K8s API, it needs this token. Only disable for apps that don't interact with K8s.",
    },
    {
        "control_id": "C-0038",
        "title": "Host PID/IPC privileges",
        "scanner": "kubescape",
        "description": "Pods should not use host PID or IPC namespaces",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": """apiVersion: apps/v1
kind: {{resource_kind}}
metadata:
  name: {{resource_name}}
  namespace: {{namespace}}
spec:
  template:
    spec:
      hostPID: false
      hostIPC: false
""",
        "notes": "Disables host PID and IPC sharing.",
    },
    {
        "control_id": "C-0041",
        "title": "HostNetwork access",
        "scanner": "kubescape",
        "description": "Pods should not have host network access",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "medium",
        "patch_template": """apiVersion: apps/v1
kind: {{resource_kind}}
metadata:
  name: {{resource_name}}
  namespace: {{namespace}}
spec:
  template:
    spec:
      hostNetwork: false
""",
        "notes": "WARNING: Ingress controllers and CNI plugins may need hostNetwork.",
    },
    {
        "control_id": "C-0044",
        "title": "Container hostPort",
        "scanner": "kubescape",
        "description": "Containers should not use hostPort",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "medium",
        "patch_template": """# Manual fix required: Remove hostPort from container port definitions
# Edit the resource and remove 'hostPort' field from spec.template.spec.containers[*].ports[*]
# Resource: {{resource_kind}}/{{resource_name}} in namespace {{namespace}}
#
# kubectl edit {{resource_kind_lower}} {{resource_name}} -n {{namespace}}
# Then remove any 'hostPort: <number>' lines from the ports section
""",
        "patch_type": "manual",
        "notes": "hostPort binds a container port directly to the node. Use NodePort services or Ingress instead.",
    },
    {
        "control_id": "C-0046",
        "title": "Insecure capabilities",
        "scanner": "kubescape",
        "description": "Containers should drop all capabilities and add only required ones",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": """apiVersion: apps/v1
kind: {{resource_kind}}
metadata:
  name: {{resource_name}}
  namespace: {{namespace}}
spec:
  template:
    spec:
      containers:
      - name: "*"
        securityContext:
          capabilities:
            drop:
              - ALL
            add:
              - NET_BIND_SERVICE
""",
        "notes": "Drops ALL capabilities and adds only NET_BIND_SERVICE (needed for ports < 1024). Remove the 'add' section if not needed.",
    },
    {
        "control_id": "C-0050",
        "title": "Resources CPU request",
        "scanner": "kubescape",
        "description": "Containers should have CPU requests",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": _workload_resource_patch("requests", "100m", "128Mi"),
        "notes": "Sets CPU request. Adjust based on actual usage.",
    },
    {
        "control_id": "C-0055",
        "title": "Linux hardening",
        "scanner": "kubescape",
        "description": "Container should have seccomp, AppArmor, and drop capabilities",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": """apiVersion: apps/v1
kind: {{resource_kind}}
metadata:
  name: {{resource_name}}
  namespace: {{namespace}}
spec:
  template:
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: "*"
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
              - ALL
""",
        "notes": "Applies Linux hardening: seccomp RuntimeDefault + drop all capabilities + no privilege escalation.",
    },
    {
        "control_id": "C-0056",
        "title": "Configured liveness probe",
        "scanner": "kubescape",
        "description": "Containers should have liveness probes",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": _workload_probe_patch("livenessProbe"),
        "notes": "Adjust path/port for your application.",
    },
    {
        "control_id": "C-0057",
        "title": "Privileged container",
        "scanner": "kubescape",
        "description": "Containers should not run in privileged mode",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": _workload_security_context_patch("privileged", "false"),
        "notes": "Disables privileged mode.",
    },
    {
        "control_id": "C-0086",
        "title": "Ensure seccomp profile is set",
        "scanner": "kubescape",
        "description": "Pod should have a seccomp profile",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": """apiVersion: apps/v1
kind: {{resource_kind}}
metadata:
  name: {{resource_name}}
  namespace: {{namespace}}
spec:
  template:
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault
""",
        "notes": "Sets pod-level seccomp profile to RuntimeDefault.",
    },
    {
        "control_id": "C-0030",
        "title": "Ingress and Egress blocked",
        "scanner": "kubescape",
        "description": "Namespace should have network policies for ingress and egress",
        "applicable_kinds": ["Namespace", "Deployment", "StatefulSet"],
        "risk_level": "medium",
        "patch_type": "network_policy",
        "patch_template": """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-{{resource_name}}
  namespace: {{namespace}}
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: {{namespace}}
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: {{namespace}}
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
""",
        "notes": "Creates a default-deny NetworkPolicy that allows traffic only within the same namespace + DNS. Adjust ingress/egress rules for your service mesh.",
    },
    {
        "control_id": "C-0270",
        "title": "Ensure CPU limits are set",
        "scanner": "kubescape",
        "description": "Containers should have CPU limits",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": _workload_resource_patch("limits", "500m", "256Mi"),
        "notes": "Adds CPU limits. Check metrics first.",
    },
    {
        "control_id": "C-0271",
        "title": "Ensure memory limits are set",
        "scanner": "kubescape",
        "description": "Containers should have memory limits",
        "applicable_kinds": _WL_KINDS,
        "risk_level": "low",
        "patch_template": _workload_resource_patch("limits", "500m", "256Mi"),
        "notes": "Adds memory limits. Check metrics first.",
    },
    {
        "control_id": "C-0054",
        "title": "Cluster internal networking",
        "scanner": "kubescape",
        "description": "Namespace should have network policies",
        "applicable_kinds": ["Namespace"],
        "risk_level": "medium",
        "patch_type": "network_policy",
        "patch_template": """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: {{namespace}}
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
""",
        "notes": "Creates a default-deny-all network policy for the namespace. You will need to add specific allow rules for your services.",
    },
]


async def seed_control_fixes(db: AsyncSession) -> None:
    """Insert seed control fixes if they don't exist."""
    result = await db.execute(select(ControlFix.control_id))
    existing = {row[0] for row in result.all()}

    inserted = 0
    for item in SEED_DATA:
        if item["control_id"] in existing:
            continue
        fix = ControlFix(
            control_id=item["control_id"],
            title=item["title"],
            scanner=item["scanner"],
            description=item.get("description"),
            patch_type=item.get("patch_type", "strategic_merge"),
            applicable_kinds=item.get("applicable_kinds"),
            patch_template=item["patch_template"],
            notes=item.get("notes"),
            risk_level=item.get("risk_level", "low"),
        )
        db.add(fix)
        inserted += 1

    if inserted:
        await db.commit()
        logger.info("Seeded %d control fix templates", inserted)
