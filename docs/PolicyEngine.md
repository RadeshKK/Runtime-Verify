# Policy Engine & Enforcement

The `policy` module determines actions to take based on the output of the Detector Engine. It acts as the brain for mitigation and enforcement.

## Policy Schema

Policies are declared in YAML. A policy defines triggers (detector outputs) and actions (mitigation strategies).

```yaml
version: "1.0"
policy_name: "restrict-filesystem-access"
rules:
  - id: "unauthorized-write-attempt"
    detector_property_id: "forbidden-write-path"
    condition: "severity == 'CRITICAL'"
    actions:
      - type: "log"
        level: "warning"
      - type: "kill_process"
        target: "actor.pid"
      - type: "send_alert"
        destination: "webhook-slack"
```

## Mitigation Action Registry

Developers can register custom action handlers to execute specialized responses:

```python
@register_action("kill_process")
def handle_kill(actor_pid: int):
    # Kill implementation
    os.kill(actor_pid, signal.SIGKILL)
```
