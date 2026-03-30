"""Generate kubectl patch YAML from a control fix template + finding metadata."""


def render_patch(
    template: str,
    patch_type: str,
    resource_kind: str,
    resource_name: str,
    namespace: str,
    control_id: str,
) -> tuple[str, str]:
    """Render a patch template and build the kubectl command.

    Returns (rendered_yaml, kubectl_command).
    """
    replacements = {
        "{{resource_kind}}": resource_kind,
        "{{resource_kind_lower}}": resource_kind.lower(),
        "{{resource_name}}": resource_name,
        "{{namespace}}": namespace or "default",
        "{{control_id}}": control_id,
    }

    rendered = template
    for placeholder, value in replacements.items():
        rendered = rendered.replace(placeholder, value)

    ns_flag = f" -n {namespace}" if namespace else ""
    kind_lower = resource_kind.lower()

    if patch_type == "json_patch":
        cmd = f"kubectl patch {kind_lower} {resource_name}{ns_flag} --type=json -p '{rendered.strip()}'"
    elif patch_type == "kubectl_set":
        cmd = rendered.strip()
    else:
        # strategic_merge or apply
        cmd = f"kubectl apply -f fix-{control_id.lower()}-{resource_name}.yaml"

    return rendered, cmd
