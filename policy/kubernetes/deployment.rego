package main

import rego.v1

# This bundle is a deterministic preflight gate for rendered Deployment
# candidates. It deliberately does not calculate risk probabilities or
# authorize/execute production changes.

deny contains msg if {
	input.kind == "Deployment"
	pod_spec := object.get(object.get(object.get(input, "spec", {}), "template", {}), "spec", {})
	object.get(pod_spec, "hostNetwork", false) == true
	msg := sprintf("Deployment %q must not use hostNetwork", [object.get(object.get(input, "metadata", {}), "name", "<unknown>")])
}

deny contains msg if {
	input.kind == "Deployment"
	pod_spec := object.get(object.get(object.get(input, "spec", {}), "template", {}), "spec", {})
	object.get(pod_spec, "hostPID", false) == true
	msg := sprintf("Deployment %q must not use hostPID", [object.get(object.get(input, "metadata", {}), "name", "<unknown>")])
}

deny contains msg if {
	input.kind == "Deployment"
	pod_spec := object.get(object.get(object.get(input, "spec", {}), "template", {}), "spec", {})
	containers := object.get(pod_spec, "containers", [])
	some container in containers
	security := object.get(container, "securityContext", {})
	object.get(security, "privileged", false) == true
	msg := sprintf("Deployment %q container %q must not run privileged", [
		object.get(object.get(input, "metadata", {}), "name", "<unknown>"),
		object.get(container, "name", "<unknown>"),
	])
}

deny contains msg if {
	input.kind == "Deployment"
	pod_spec := object.get(object.get(object.get(input, "spec", {}), "template", {}), "spec", {})
	containers := object.get(pod_spec, "containers", [])
	some container in containers
	container_security := object.get(container, "securityContext", {})
	pod_security := object.get(pod_spec, "securityContext", {})
	run_as_non_root := object.get(container_security, "runAsNonRoot", object.get(pod_security, "runAsNonRoot", false))
	run_as_non_root != true
	msg := sprintf("Deployment %q container %q must set runAsNonRoot=true", [
		object.get(object.get(input, "metadata", {}), "name", "<unknown>"),
		object.get(container, "name", "<unknown>"),
	])
}

deny contains msg if {
	input.kind == "Deployment"
	pod_spec := object.get(object.get(object.get(input, "spec", {}), "template", {}), "spec", {})
	containers := object.get(pod_spec, "containers", [])
	some container in containers
	resources := object.get(container, "resources", {})
	requests := object.get(resources, "requests", {})
	object.get(requests, "cpu", null) == null
	msg := sprintf("Deployment %q container %q must define CPU requests", [
		object.get(object.get(input, "metadata", {}), "name", "<unknown>"),
		object.get(container, "name", "<unknown>"),
	])
}

deny contains msg if {
	input.kind == "Deployment"
	pod_spec := object.get(object.get(object.get(input, "spec", {}), "template", {}), "spec", {})
	containers := object.get(pod_spec, "containers", [])
	some container in containers
	resources := object.get(container, "resources", {})
	requests := object.get(resources, "requests", {})
	object.get(requests, "memory", null) == null
	msg := sprintf("Deployment %q container %q must define memory requests", [
		object.get(object.get(input, "metadata", {}), "name", "<unknown>"),
		object.get(container, "name", "<unknown>"),
	])
}

deny contains msg if {
	input.kind == "Deployment"
	pod_spec := object.get(object.get(object.get(input, "spec", {}), "template", {}), "spec", {})
	containers := object.get(pod_spec, "containers", [])
	some container in containers
	resources := object.get(container, "resources", {})
	limits := object.get(resources, "limits", {})
	object.get(limits, "cpu", null) == null
	msg := sprintf("Deployment %q container %q must define CPU limits", [
		object.get(object.get(input, "metadata", {}), "name", "<unknown>"),
		object.get(container, "name", "<unknown>"),
	])
}

deny contains msg if {
	input.kind == "Deployment"
	pod_spec := object.get(object.get(object.get(input, "spec", {}), "template", {}), "spec", {})
	containers := object.get(pod_spec, "containers", [])
	some container in containers
	resources := object.get(container, "resources", {})
	limits := object.get(resources, "limits", {})
	object.get(limits, "memory", null) == null
	msg := sprintf("Deployment %q container %q must define memory limits", [
		object.get(object.get(input, "metadata", {}), "name", "<unknown>"),
		object.get(container, "name", "<unknown>"),
	])
}

deny contains msg if {
	input.kind == "Deployment"
	pod_spec := object.get(object.get(object.get(input, "spec", {}), "template", {}), "spec", {})
	containers := object.get(pod_spec, "containers", [])
	some container in containers
	image := object.get(container, "image", "")
	not regex.match("^[^@]+@sha256:[a-f0-9]{64}$", image)
	msg := sprintf("Deployment %q container %q must use an immutable sha256 image reference", [
		object.get(object.get(input, "metadata", {}), "name", "<unknown>"),
		object.get(container, "name", "<unknown>"),
	])
}
