<!-- :warning: **This project is a work in progress** -->
:construction: **This project is a [work in progress](https://claude.ai/chat/bc7238ad-31af-4fd1-b594-102df36b6f1a)**

  

# sw_supply_chain_security_toolkit--sigstore--cosign
Tutorial &amp; example project for **sw supply chain security**  using **sigstore, syft, cosigen, rekor, OPA** etc tools

## Software Supply Chain Security Tutorial Outline
### A Hands-On Learning Path for Ubuntu Systems

---

## **Overview**

This tutorial teaches essential software supply chain security concepts using industry-standard open-source tools. By the end, you'll understand how to sign artifacts, generate SBOMs, verify signatures, create build attestations, and enforce security policies.

**Target Audience:** Developers, DevOps engineers, and security professionals looking to implement supply chain security best practices.

**Prerequisites:**
- Ubuntu 22.04 or 24.04 system (local or VM)
- Basic Docker/container knowledge
- Git basics
- Command-line proficiency
- GitHub account (for keyless signing demos)

---

## **Module 1: Foundations & Environment Setup (30 minutes)**

### 1.1 Understanding Software Supply Chain Security
- **Concepts covered:**
  - What is supply chain security and why it matters
  - Real-world attack examples (SolarWinds, XZ backdoor, NPM flooding)
  - The trust problem in modern software development
  - Overview of SLSA framework (Supply-chain Levels for Software Artifacts)
  - SBOM basics (Software Bill of Materials)

### 1.2 Setting Up Your Ubuntu Environment
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install essential tools
sudo apt install -y curl git jq build-essential

# Install Docker (if not present)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

### 1.3 Directory Structure
Create a working directory for hands-on exercises:
```bash
mkdir -p ~/supply-chain-security/{artifacts,keys,sboms,policies}
cd ~/supply-chain-security
```

---

## **Module 2: Artifact Signing with Sigstore & Cosign (90 minutes)**

### 2.1 Understanding Sigstore Ecosystem
- **Components overview:**
  - **Cosign**: CLI tool for signing containers and artifacts
  - **Fulcio**: Certificate Authority for keyless signing
  - **Rekor**: Transparency log for signature verification
  - **Sigstore Public Good Infrastructure**

### 2.2 Installing Cosign
```bash
# Install latest Cosign
LATEST_VERSION=$(curl https://api.github.com/repos/sigstore/cosign/releases/latest | grep tag_name | cut -d : -f 2,3 | tr -d \" | tr -d , | tr -d " ")
curl -Lo cosign https://github.com/sigstore/cosign/releases/download/${LATEST_VERSION}/cosign-linux-amd64
chmod +x cosign
sudo mv cosign /usr/local/bin/
cosign version
```

### 2.3 Hands-On Lab 1: Traditional Key-Based Signing
**Exercise: Sign a container image using generated keypair**
```bash
# Generate key pair
cosign generate-key-pair

# Build sample container
cat > Dockerfile <<EOF
FROM alpine:latest
RUN echo "Hello Supply Chain Security" > /message.txt
CMD ["cat", "/message.txt"]
EOF

docker build -t localhost:5000/demo-app:v1.0 .

# Sign the container
cosign sign --key cosign.key localhost:5000/demo-app:v1.0

# Verify signature
cosign verify --key cosign.pub localhost:5000/demo-app:v1.0
```

**Learning objectives:**
- Generate and secure signing keys
- Sign container images
- Verify signatures
- Understand signature storage in OCI registries

### 2.4 Hands-On Lab 2: Keyless Signing with OIDC
**Exercise: Implement keyless signing using GitHub identity**

```bash
# Create temporary image repository (using ttl.sh)
export IMAGE_URI=ttl.sh/$(uuidgen | head -c 8 | tr 'A-Z' 'a-z'):1h
docker tag localhost:5000/demo-app:v1.0 $IMAGE_URI
docker push $IMAGE_URI

# Keyless signing (opens browser for OIDC auth)
cosign sign $IMAGE_URI

# Verify with identity
cosign verify $IMAGE_URI \
  --certificate-identity-regexp=.* \
  --certificate-oidc-issuer-regexp=.*
```

**Learning objectives:**
- Understand OIDC-based authentication
- Work with ephemeral keys and short-lived certificates
- Query Rekor transparency log
- Verify keyless signatures

### 2.5 Deep Dive: Rekor Transparency Log
**Exercise: Manually interact with Rekor**
```bash
# Install rekor-cli
go install github.com/sigstore/rekor/cmd/rekor-cli@latest

# Search for entries by email
rekor-cli search --email your-email@example.com

# Get specific log entry
rekor-cli get --uuid <uuid-from-search>

# Verify log entry inclusion
rekor-cli verify --artifact message.txt \
  --signature message.txt.sig \
  --public-key cosign.pub \
  --pki-format x509
```

**Learning objectives:**
- Understand append-only transparency logs
- Query and verify log entries
- Audit signing events

---

## **Module 3: Software Bill of Materials (SBOM) Generation (60 minutes)**

### 3.1 Understanding SBOMs
- **What and why:**
  - Complete inventory of software components
  - Regulatory requirements (US EO 14028)
  - Vulnerability management enabler
  - License compliance tracking

- **SBOM formats:**
  - SPDX (Linux Foundation)
  - CycloneDX (OWASP)
  - Comparison and use cases

### 3.2 Installing Syft
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
syft version
```

### 3.3 Hands-On Lab 3: Generating SBOMs
**Exercise: Create SBOMs in multiple formats**

```bash
# Basic SBOM for container image
syft alpine:latest

# Generate SBOM in SPDX JSON format
syft alpine:latest -o spdx-json=sboms/alpine-spdx.json

# Generate SBOM in CycloneDX format
syft alpine:latest -o cyclonedx-json=sboms/alpine-cdx.json

# SBOM for filesystem/directory
syft dir:./my-application -o json=sboms/app-sbom.json

# Include all image layers
syft alpine:latest --scope all-layers -o json

# Scan from different sources
syft docker:nginx:latest
syft registry:alpine:latest
syft docker-archive:image.tar
```

**Learning objectives:**
- Generate SBOMs from various sources
- Understand different SBOM formats
- Inspect dependency trees
- Work with direct and transitive dependencies

### 3.4 Hands-On Lab 4: Attesting and Signing SBOMs
**Exercise: Combine Syft with Cosign for signed attestations**

```bash
# Generate and sign SBOM attestation
syft $IMAGE_URI -o spdx-json | \
  cosign attest --predicate - --type spdx $IMAGE_URI

# Verify attestation
cosign verify-attestation $IMAGE_URI \
  --certificate-identity-regexp=.* \
  --certificate-oidc-issuer-regexp=.* \
  --type spdx | jq -r .payload | base64 -d | jq
```

**Learning objectives:**
- Create cryptographic attestations
- Link SBOMs to artifacts
- Verify SBOM authenticity

---

## **Module 4: Policy Enforcement with Open Policy Agent (75 minutes)**

### 4.1 Understanding Policy as Code
- **OPA fundamentals:**
  - Declarative policy language (Rego)
  - Decoupled decision-making
  - Universal policy engine
  - Integration points (Kubernetes, CI/CD, API gateways)

### 4.2 Installing OPA
```bash
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod 755 ./opa
sudo mv opa /usr/local/bin/
opa version
```

### 4.3 Hands-On Lab 5: Basic Rego Policies
**Exercise: Write supply chain security policies**

Create `policies/supply-chain.rego`:
```rego
package supplychain

import future.keywords.if
import future.keywords.in

# Deny unsigned images
deny_unsigned if {
    not input.signed
}

# Require specific signer
deny_invalid_signer if {
    input.signed
    not input.signer_email in allowed_signers
}

allowed_signers := {
    "trusted-dev@company.com",
    "ci-bot@company.com"
}

# Check SBOM presence
deny_missing_sbom if {
    not input.has_sbom
}

# Deny critical vulnerabilities
deny_critical_vulns if {
    some vuln in input.vulnerabilities
    vuln.severity == "CRITICAL"
    not vuln.id in accepted_risks
}

accepted_risks := set()
```

**Test the policy:**
```bash
# Create test input
cat > test-input.json <<EOF
{
  "signed": true,
  "signer_email": "trusted-dev@company.com",
  "has_sbom": true,
  "vulnerabilities": []
}
EOF

# Evaluate policy
opa eval -i test-input.json -d policies/supply-chain.rego \
  "data.supplychain.deny_unsigned"
```

### 4.4 Hands-On Lab 6: Kubernetes Admission Control
**Exercise: Deploy OPA Gatekeeper for supply chain policies**

```bash
# Install Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

# Create constraint template for signed images
cat > constraint-template.yaml <<EOF
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiresignedimages
spec:
  crd:
    spec:
      names:
        kind: K8sRequireSignedImages
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiresignedimages
        
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not is_signed(container.image)
          msg := sprintf("Container image %v is not signed", [container.image])
        }
        
        is_signed(image) {
          # Integration with Cosign verification would go here
          # For demo, check annotation
          input.review.object.metadata.annotations["cosign.verified"] == "true"
        }
EOF

kubectl apply -f constraint-template.yaml
```

### 4.5 Hands-On Lab 7: CI/CD Pipeline Policy
**Exercise: GitHub Actions workflow with OPA checks**

Create `.github/workflows/supply-chain-security.yaml`:
```yaml
name: Supply Chain Security

on: [push, pull_request]

jobs:
  security-checks:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      packages: write
      
    steps:
      - uses: actions/checkout@v3
      
      - name: Install tools
        run: |
          # Install Cosign
          curl -Lo cosign https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
          chmod +x cosign && sudo mv cosign /usr/local/bin/
          
          # Install Syft
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          
          # Install OPA
          curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
          chmod +x opa && sudo mv opa /usr/local/bin/
      
      - name: Build image
        run: docker build -t ghcr.io/${{ github.repository }}:${{ github.sha }} .
      
      - name: Generate SBOM
        run: |
          syft ghcr.io/${{ github.repository }}:${{ github.sha }} \
            -o spdx-json=sbom.json
      
      - name: Check policy
        run: |
          # Create policy check input
          cat > policy-input.json <<EOF
          {
            "image": "ghcr.io/${{ github.repository }}:${{ github.sha }}",
            "has_sbom": true,
            "sbom_path": "sbom.json"
          }
          EOF
          
          # Evaluate against policy
          opa eval -i policy-input.json -d .github/policies/ \
            "data.cicd.allow" --fail
      
      - name: Sign image (keyless)
        run: |
          echo "${{ secrets.GITHUB_TOKEN }}" | docker login ghcr.io -u $ --password-stdin
          docker push ghcr.io/${{ github.repository }}:${{ github.sha }}
          cosign sign --yes ghcr.io/${{ github.repository }}:${{ github.sha }}
      
      - name: Attest SBOM
        run: |
          cosign attest --yes --predicate sbom.json --type spdx \
            ghcr.io/${{ github.repository }}:${{ github.sha }}
```

**Learning objectives:**
- Write declarative security policies
- Integrate OPA with CI/CD
- Automate policy enforcement
- Block non-compliant deployments

---

## **Module 5: SLSA Compliance & Build Attestations (60 minutes)**

### 5.1 Understanding SLSA Levels
- **Level 0:** No guarantees
- **Level 1:** Build process exists and is documented
- **Level 2:** Hosted build with signed provenance
- **Level 3:** Hardened builds with source and build platform security
- **Level 4:** Highest assurance with two-party review

### 5.2 Hands-On Lab 8: Generate SLSA Provenance
**Exercise: Create build provenance metadata**

```bash
# Install slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Generate provenance (simplified example)
cat > provenance.json <<EOF
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "ghcr.io/yourorg/demo-app",
      "digest": {
        "sha256": "$(docker inspect --format='{{.Id}}' localhost:5000/demo-app:v1.0 | cut -d: -f2)"
      }
    }
  ],
  "predicate": {
    "builder": {
      "id": "https://github.com/yourorg/builder"
    },
    "buildType": "https://github.com/yourorg/docker-build@v1",
    "invocation": {
      "configSource": {
        "uri": "git+https://github.com/yourorg/demo-app",
        "digest": {
          "sha256": "$(git rev-parse HEAD)"
        }
      }
    },
    "materials": [
      {
        "uri": "git+https://github.com/yourorg/demo-app",
        "digest": {
          "sha256": "$(git rev-parse HEAD)"
        }
      }
    ]
  }
}
EOF

# Attest provenance
cosign attest --predicate provenance.json --type slsaprovenance \
  localhost:5000/demo-app:v1.0
```

### 5.3 Hands-On Lab 9: Implementing SLSA Level 2
**Exercise: GitHub Actions with SLSA attestations**

Use GitHub's official SLSA builder:
```yaml
name: SLSA Build

on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read
  packages: write

jobs:
  build:
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.9.0
    with:
      image: ghcr.io/${{ github.repository }}
      digest: ${{ needs.build.outputs.digest }}
    secrets:
      registry-username: ${{ github.actor }}
      registry-password: ${{ secrets.GITHUB_TOKEN }}
```

**Learning objectives:**
- Understand build provenance
- Generate SLSA-compliant attestations
- Verify build integrity
- Achieve SLSA Level 2 compliance

---

## **Module 6: Complete Workflow Integration (90 minutes)**

### 6.1 Hands-On Lab 10: End-to-End Secure Pipeline
**Exercise: Build a complete secure software supply chain**

**Project structure:**
```
secure-app/
├── .github/
│   ├── workflows/
│   │   └── secure-pipeline.yaml
│   └── policies/
│       ├── supply-chain.rego
│       └── vulnerabilities.rego
├── Dockerfile
├── app/
│   └── main.go
└── README.md
```

**Complete workflow implementing:**
1. Code checkout with verification
2. Dependency scanning
3. SBOM generation
4. Container build
5. Image signing (keyless)
6. Provenance attestation
7. Policy enforcement
8. Deployment with verification

**Deployment verification script:**
```bash
#!/bin/bash
set -e

IMAGE=$1
POLICY_DIR="policies"

echo "=== Verifying Supply Chain Security ==="

# 1. Verify signature
echo "Checking signature..."
cosign verify $IMAGE \
  --certificate-identity-regexp=.* \
  --certificate-oidc-issuer-regexp=.*

# 2. Extract and verify SBOM
echo "Checking SBOM attestation..."
cosign verify-attestation $IMAGE \
  --certificate-identity-regexp=.* \
  --certificate-oidc-issuer-regexp=.* \
  --type spdx | jq -r .payload | base64 -d > sbom.json

# 3. Run policy checks
echo "Evaluating policies..."
opa eval -i sbom.json -d $POLICY_DIR "data.deployment.allow" --fail

# 4. Verify provenance
echo "Checking build provenance..."
cosign verify-attestation $IMAGE \
  --certificate-identity-regexp=.* \
  --certificate-oidc-issuer-regexp=.* \
  --type slsaprovenance

echo "=== All checks passed! Image is verified ==="
```

### 6.2 Hands-On Lab 11: Monitoring and Auditing
**Exercise: Set up supply chain monitoring**

```bash
# Query Rekor for your signing activity
rekor-cli search --email your-email@example.com

# Monitor for unexpected signatures
#!/bin/bash
EXPECTED_IDENTITIES=("ci@company.com" "approved-dev@company.com")

rekor-cli search --email "*@company.com" --format json | \
  jq -r '.[] | .body.identity.email' | \
  while read email; do
    if [[ ! " ${EXPECTED_IDENTITIES[@]} " =~ " ${email} " ]]; then
      echo "ALERT: Unexpected signing identity: $email"
    fi
  done
```

---

## **Module 7: Best Practices & Production Considerations (45 minutes)**

### 7.1 Key Management Best Practices
- Rotating keys securely
- Hardware security modules (HSM) integration
- Cloud KMS integration (AWS KMS, GCP KMS, Azure Key Vault)
- Secrets management (HashiCorp Vault, Kubernetes secrets)

### 7.2 Private Infrastructure
**When to run your own:**
- Private Fulcio CA instance
- Private Rekor transparency log
- Private Sigstore TSA (Timestamp Authority)
- Configuration and setup considerations

### 7.3 Policy Management at Scale
- Centralized policy repositories
- Policy testing frameworks
- Versioning and rollback strategies
- Team ownership models

### 7.4 Compliance and Auditing
- Regulatory requirements (SOC 2, ISO 27001, FedRAMP)
- Audit trail maintenance
- Incident response procedures
- Continuous compliance monitoring

---

## **Module 8: Advanced Topics (Optional, 60 minutes)**

### 8.1 Signing Other Artifact Types
- Helm charts
- Tekton bundles
- WASM modules
- Generic blobs and binaries
- Git commits

### 8.2 Multi-Signature Requirements
```rego
# OPA policy requiring multiple signers
package multisig

import future.keywords

required_signers := {
    "security-team@company.com",
    "platform-team@company.com"
}

deny_insufficient_signatures if {
    count(input.signatures) < 2
}

deny_missing_required_signer if {
    some required in required_signers
    not required in {sig.identity | sig := input.signatures[_]}
}
```

### 8.3 Supply Chain Levels for ML Models
- Signing model artifacts
- Data provenance
- Training pipeline attestations

### 8.4 Integration with Cloud Platforms
- AWS ECS/EKS with supply chain security
- GCP Cloud Run verification
- Azure Container Apps attestation
- Serverless deployments

---

## **Assessment & Certification**

### Final Project: Secure a Real Application
Build, sign, attest, and deploy a complete application with:
- Multi-stage Dockerfile
- SBOM generation
- Keyless signing
- SLSA Level 2 compliance
- OPA policy enforcement
- Monitoring and alerting
- Complete documentation

### Success Criteria:
✅ All artifacts are signed  
✅ SBOMs are generated and attested  
✅ Build provenance is created  
✅ Policies prevent unsigned deployments  
✅ Transparency log entries are verifiable  
✅ Zero critical vulnerabilities in production  
✅ Complete audit trail exists  

---

## **Resources & Further Learning**

### Official Documentation
- Sigstore: https://docs.sigstore.dev
- Cosign: https://github.com/sigstore/cosign
- OPA: https://www.openpolicyagent.org/docs
- SLSA: https://slsa.dev
- Syft: https://github.com/anchore/syft

### Community
- CNCF Slack (Sigstore, OPA channels)
- OpenSSF working groups
- SLSA community meetings

### Additional Tools
- Grype: Vulnerability scanning
- Trivy: Container security
- Kyverno: Kubernetes-native policy engine
- Ratify: Supply chain artifact verification
- GUAC: Graph for Understanding Artifact Composition

---
