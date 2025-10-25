## **Example project for this tutorial**

```
sigstore-lab/
    ├── Dockerfile
    ├── Makefile          # Use the extended Makefile with Rekor + policy gate
    └── src/
        └── app.py
```

### **src/app.py**

```python
print("Hello from sigstore-lab demo app!")
```

### **Dockerfile**

```dockerfile
FROM python:3.12-slim      # Base image          
WORKDIR /app               # Set working directory
COPY src/app.py .          # Copy application code
CMD ["python3", "app.py"]  # Default command
```

### **Makefile workflow**

```bash
IMAGE = sigstore-lab:local
SBOM  = sbom.cdx.json
REKOR = http://localhost:3000

# Start local Rekor server (required by the cosign tool to log the image signing event) 
  `docker run -d --name rekor -p 3000:3000 gcr.io/projectsigstore/rekor-server:latest`

make build   # Docker image is built locally
             #
             #   `docker build -t $(IMAGE) .`

make sbom    # Generate SBOM - Syft analyzes the image, producing a **CycloneDX SBOM**
             #
             #   `syft $(IMAGE) -o cyclonedx-json > $(SBOM)`

make sign    # Use cosign for Keyless signing + Rekor entry
             #   Cosign attaches the SBOM to the image as an **attestation**
             #   Cosign signs the image (or attestation) with a `local key` or `keyless method`
             #   Guarantees **integrity and authenticity**
             #
             #   `cosign sign --type cyclonedx --predicate $(SBOM) $(IMAGE)`

make verify  #  Use Cosign to verify the signature + attestation before deployment
             #
             #   `cosign verify-attestation --type cyclonedx $(IMAGE)`
```



## **simplified diagram of the sigstore-lab workflow with `Cosign`, `SBOM`, and `attestation`**:

`**offline/local workflow**` vs `**production workflow** with keyless signing and Rekor`, highlighting the differences:

```
┌─────────────────────┐                     ┌────────────────────────────┐
│   Offline / Local   │                     │  Production / Keyless +    │
│       sigstore-lab  │                     │      Rekor Flow            │
└─────────┬───────-───┘                     └────────────┬───────────────┘
          │ docker build                                 │ `docker build -t $(IMAGE) .`
          ▼                                              ▼
┌─────────────────────┐                     ┌─────────────────────────────┐
│ Local Docker Image  │  sigstore-lab:local │ Local Docker Image          │ same image
└─────────┬─────-─────┘                     └────────────┬────-───────────┘
          │ syft                                         │ `syft $(IMAGE) -o cyclonedx-json > $(SBOM)`
          ▼                                              ▼  Generate SBOM
┌─────────────────────┐                     ┌─────────────────────────────┐
│ SBOM JSON           │  sbom.cdx.json      │ SBOM JSON                   │ sbom.cdx.json
└─────────┬────────-──┘                     └────────────┬─-──────────────┘
          │ cosign attest                                │ cosign attest
          ▼                                              ▼  
┌─────────────────────┐                     ┌─────────────────────────────┐
│ Attested Image      │ metadata + SBOM     │ Attested Image              │ metadata + SBOM
└─────────┬────-──────┘                     └────────────┬───-────────────┘
          │ cosign sign (local key)                      │ cosign sign (keyless/ephemeral)
          ▼                                              ▼
┌─────────────────────┐                     ┌─────────────────────────────┐
│ Signed Image        │ trusted locally     │ Signed Image + Rekor Entry  │
└─────────┬──-────────┘                     └────────────┬──-─────────────┘
          │ cosign verify                                │ cosign verify / verify-attestation
          ▼                                              ▼
┌─────────────────────┐                     ┌─────────────────────────────┐
│ Trusted Image       │ deployable locally  │ Trusted Image               │ deployable with verified attestation + Rekor
└─────────────────────┘                     └─────────────────────────────┘

```

## :toolbox: Toolbox

**Sigstore**:
* **Sigstore** is a transparent, non-profit open-source project that enhances **software supply chain security** by making it easy for developers to `cryptographically sign software artifacts`. 
* It provides a `suite of tools, including Cosign, Fulcio, and Rekor`, to `create and verify digital signatures` `without the hassle of key management`. 

**Cosign**
* **Cosign** is a command-line **utility for signing and verifying software artifacts** like container images and blobs.
* As part of the Sigstore project, it `simplifies code signing` by using an `ephemeral key pair` to sign artifacts and recording the signature in a `transparency log`. 

**Keyless signing**
* **Keyless signing** is a method used by Cosign that **eliminates the need to manage long-term private keys**. 
* It works by using an `OpenID Connect (OIDC) identity` to request a `short-lived certificate` from `Fulcio`, which is then used to sign the artifact. 

**Fulcio**
* **Fulcio** is the **certificate authority within the Sigstore ecosystem** that `issues` `short-lived, code-signing certificates`. 
* It `authenticates` a user's `identity` via an `OpenID Connect (OIDC) provider` and `binds that identity` `to` a `temporary public key`. 

**Rekor**
* **Rekor** is a **transparency log** that **acts as a public, tamper-resistant ledger** for software artifact signatures and metadata.
* It provides an `immutable, timestamped record` of `signing events` that anyone can verify for auditing purposes. 

**OPA (Open Policy Agent)**
* **OPA** is an open-source, general-purpose policy engine that enables policy-based control for various software stacks, including Kubernetes deployments.
* It is used to enforce policies as code, allowing you to define rules about what can and cannot be deployed or executed. 

***

 
## Cosign 

With **Cosign**, the goal is to **cryptographically secure container images and other artifacts** to prevent tampering and enable trust in software supply chains.

---

### **What Cosign does**

1. **Sign images or artifacts**

   * Attaches a **digital signature** to a container image, SBOM, or other artifact.
   * Ensures **integrity**: the image has not been modified since signing.
   * Can be done with:

     * **Local keys** (private/public keypair)
     * **Keyless signing** (via OIDC and ephemeral keys)

2. **Verify signatures**

   * Confirms that a given image or artifact was signed by a trusted key.
   * Prevents deploying unverified or malicious images.

3. **Generate and verify attestations**

   * Attach **metadata**, such as an SBOM, provenance info, or policy compliance.
   * Example: “This image was built from source commit X, and contains SBOM Y.”
   * Enables automated **supply-chain security checks**.

4. **Integrate into CI/CD**

   * Signing images as part of the build process.
   * Verifying signatures before deployment.
   * Enforcing **policy gates** using tools like **Rekor + OPA/Conftest**.

---

### **Why we use Cosign**

1. **Supply-chain security**

   * Prevents untrusted or tampered images from being deployed.
   * Ensures images come from the intended build process.

2. **Reproducibility and traceability**

   * Attestations let you track **who built the image, from what source, and what dependencies** were included.

3. **Regulatory and compliance**

   * Required for high-assurance environments (e.g., SBOM attestations for government/enterprise use).

4. **Future-proofing**

   * Supports **keyless ephemeral signing** and **transparency logs (Rekor)**.
   * Works with container registries, SBOMs, and CI/CD pipelines.

---

In short: **Cosign makes your container images and artifacts verifiable and trustworthy**, letting you safely deploy software in automated pipelines without relying on implicit trust.
