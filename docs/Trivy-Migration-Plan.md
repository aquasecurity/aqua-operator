## Trivy Integration Plan (Distinct Component, Default for Kube Enforcer)

### Goal
- Introduce Trivy as a first-class, distinct component (its own CRD and controller), separate from Starboard.
- Make Trivy the default scanner used by Kube Enforcer (KE), while keeping Starboard fully supported for backward compatibility.
- Deliver with a new operator image and a new OLM bundle version.

### Scope
- Add new CRD: AquaTrivy (group `aquasecurity.github.io/v1alpha1`, kind `AquaTrivy`, plural `aquatrivies`).
- Add controller and helper for AquaTrivy to deploy and manage the Trivy Operator.
- Update KE to default to Trivy, retain Starboard code-path when requested.
- Update AquaCsp defaults to inject Trivy instead of Starboard.
- Add OLM CSV changes, related images, samples, and docs.

### Non-goals (for this iteration)
- Remove Starboard. We keep it intact for compatibility and deprecate later.
- Renaming existing Starboard artifacts. New work is additive and uses Trivy naming.

---

## Design

### New CRD: AquaTrivy
- Group/Version: `aquasecurity.github.io/v1alpha1`
- Kind: `AquaTrivy`
- Plural: `aquatrivies`
- Spec (mirrors AquaStarboard, Trivy naming):
  - `infra` (`AquaInfrastructure`)
  - `allowAnyVersion` (bool)
  - `trivy`/`deploy` (`AquaService`) – replicas, resources, image, etc. Field name: `trivyService`
  - `config` (`AquaStarboardConfig`-like with `imagePullSecret`)
  - `registry` (`AquaDockerRegistry`)
  - `image` (`AquaImage`) – optional override
  - `env` ([]corev1.EnvVar) – optional
  - Optional env flags similar to AquaStarboard (operator toggles like metrics/health, concurrency, etc.).
- Status:
  - `nodes` ([]string)
  - `state` (`AquaDeploymentState`)
- Printing columns:
  - Replicas, Age, Status, Nodes (same as AquaStarboard).

### AquaTrivy controller
- Namespace: `controllers/aquasecurity/aquatrivy`
- Responsibilities:
  - Create SA: `trivy-operator`
  - Create RBAC:
    - ClusterRole and ClusterRoleBinding for Trivy operator (parallel to Starboard RBAC with Trivy names)
  - Create Secrets/ConfigMaps:
    - ImagePullSecret reference (if provided), operator config maps (if needed)
  - Create Deployment:
    - Name: `trivy-operator`
    - Image resolution order:
      1) `RELATED_IMAGE_TRIVY`
      2) `spec.trivyService.image` overrides
      3) Defaults from constants (`docker.io/aquasec/trivy-operator:0.28.0`)
    - Security context and probes similar to AquaStarboard
  - Set owner references and status updates according to ready state.

### KE changes (default to Trivy, keep Starboard)
- Add new field to `AquaKubeEnforcerSpec`:
  - `trivy` (`AquaTrivyDetails`) – analogous to `AquaStarboardDetails`
- KE reconcile order:
  1) If `.spec.trivy` present → create/update `AquaTrivy` (new `installAquaTrivy` path).
  2) Else if `.spec.starboard` present → existing Starboard flow.
  3) Else → default create/update `AquaTrivy` with sane defaults (Trivy as default).
- KE ConfigMap logic:
  - Keep existing watcher toggles (`AQUA_WATCH_CONFIG_AUDIT_REPORT`, `AQUA_KAP_ADD_ALL_CONTROL`) when either scanner is enabled.

### AquaCsp defaults
- Switch default generation from `.spec.starboard` to `.spec.trivy` for new KE deployments created by CSP.
- Preserve Starboard example path for users explicitly setting it.

### Image resolution and constants
- Add:
  - `TrivyVersion = "0.28.0"`
  - `TrivyServiceAccount = "trivy-operator"`
  - Default registry: `docker.io/aquasec`
  - `RELATED_IMAGE_TRIVY` env handled in helper.
- Extend `GetImageData` to recognize `"trivy-operator"` and set Trivy defaults (registry/version) when applicable.

### CRDs consumed by scanner
- No change required; Trivy Operator uses Starboard report CRDs (`ConfigAuditReports`, `ClusterConfigAuditReports`, etc.) which are already present in the bundle.

---

## Implementation Steps

1) API types
- Add `apis/aquasecurity/v1alpha1/aquatrivy_types.go`:
  - Define `AquaTrivySpec`, `AquaTrivyStatus`, `AquaTrivy`, `AquaTrivyList`
  - Register with `SchemeBuilder.Register(...)`
  - Mirror fields from AquaStarboard with Trivy naming (`trivyService`)

2) Controller and helper
- Add `controllers/aquasecurity/aquatrivy/aquatrivy_controller.go`
- Add `controllers/aquasecurity/aquatrivy/aquaTrivyHelper.go`
  - RBAC rules similar to AquaStarboard; align resources to Trivy operator needs
  - SA/CR/CRB/ConfigMap/Secret/Deployment creation
  - Deployment image resolution with `RELATED_IMAGE_TRIVY`

3) KE integration
- Update `apis/operator/v1alpha1/aquakubeenforcer_types.go` to include `DeployTrivy *AquaTrivyDetails`
- In `controllers/operator/aquakubeenforcer/aquakubeenforcer_controller.go`:
  - Add reconcile path to install/update `AquaTrivy` (prefer it as default)
  - Keep existing `installAquaStarboard` unchanged
- In `controllers/operator/aquakubeenforcer/aquaKubeEnforcerHelper.go`:
  - Add `newTrivy(cr)` to construct an `AquaTrivy` CR from `.spec.trivy`
  - Preserve KE config toggles when scanner enabled

4) AquaCsp default
- Update `controllers/operator/aquacsp/aquaCspHelper.go`:
  - Generate KE CRs with `.spec.trivy` by default (Trivy version/image defaults)
  - Retain explicit Starboard sample path

5) Constants and image resolver
- `pkg/consts/consts.go`:
  - Add Trivy constants (version, SA name)
- `pkg/utils/extra/extra.go`:
  - Add branch for `"trivy-operator"` to set registry/version defaults

6) Wire-up + manifests
- `main.go`:
  - Register AquaTrivy reconciler setup
- `config/crd/bases`:
  - Generate `aquasecurity.github.io_aquatrivies.yaml`
- `config/rbac`:
  - Ensure SA/CR/CRB/RoleBinding coverage for AquaTrivy controller
- `config/samples`:
  - Add `aquasecurity_v1alpha1_aquatrivy.yaml`
  - Update KE sample to use `.spec.trivy`, keep Starboard sample

7) OLM CSV + bundle
- CSV changes:
  - Add “owned” CRD for `AquaTrivy`
  - Add env `RELATED_IMAGE_TRIVY=docker.io/aquasec/trivy-operator:0.28.0`
  - Add `relatedImages` entry for Trivy operator
  - Keep existing Starboard entries
- Build new bundle version; validate with `operator-sdk run bundle`

8) Docs and migration
- Update docs to:
  - Announce Trivy as default
  - Show how to enable Starboard explicitly for compatibility
  - Note that scanner report CRDs remain unchanged

9) Validation
- Local cluster tests:
  - Deploy CSP → KE (defaults to `.spec.trivy`) → `AquaTrivy` → `trivy-operator` Deployment
  - Verify CRDs registered, operator healthy, ConfigAuditReports/ClusterConfigAuditReports created
  - Test explicit Starboard path still functions

10) Release
- Build operator image (new version)
- Create and push bundle to community operators (new directory under manifests)
- Submit PR with `manifests/` and `metadata/annotations.yaml`

---

## Backward Compatibility
- Starboard path remains fully supported if `.spec.starboard` is set.
- Default behavior moves to Trivy only when `.spec.trivy` is present or when neither scanner is specified (default to Trivy).
- Existing CRDs for reports are unchanged.

## Risk and Mitigations
- RBAC gaps for Trivy operator: mirror Starboard RBAC and validate with test cluster; refine as needed.
- Image resolution mismatches: prefer `RELATED_IMAGE_TRIVY`, support CR overrides.
- OLM validation: use `operator-sdk` bundle validators; adjust CSV as required.

## Defaults
- Trivy Operator image: `docker.io/aquasec/trivy-operator:0.28.0`
- ServiceAccount: `trivy-operator`
- Registry default for Trivy: `docker.io/aquasec`

## Follow-up (later release)
- Deprecate Starboard in docs and samples.
- Optionally remove AquaStarboard CRD/controller after deprecation window.


