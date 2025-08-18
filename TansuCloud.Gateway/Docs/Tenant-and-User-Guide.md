# Tenant and End‑User Guide

This guide explains how people join a tenant in Tansu.cloud and how they sign in to applications that use the platform.

Audience:
- Tenant administrators who manage membership and access.
- End users who were invited or allowed to self‑register for a tenant.

---

## How a new tenant signs up

A tenant represents an organization (for example, a team, a company, or a project space). Creating a tenant is the first step before inviting people.

Typical steps:
- Go to the Dashboard home page and choose Create a new tenant.
- Enter the tenant name and an optional public subdomain (for example, acme.tansu.cloud). You can connect a custom domain later.
- Create the first administrator account by signing in on the hosted page using email and password or an external Identity Provider (for example, Google or Microsoft). Email verification is required.
- Confirm the plan (free or paid) and, if required, add billing details. This can be skipped in development environments.
- After confirmation, the first administrator is signed in to the new tenant and can invite other people and register applications.

Notes
- The first person who creates the tenant becomes an Administrator in that tenant.
- Single Sign‑On (SSO) via an external Identity Provider can be connected after the tenant is created.

---

## 1) How a new person becomes a member of a tenant

There are three supported ways to add people to a tenant.

1. Invite‑based registration (recommended)
   - A tenant administrator opens the Dashboard and sends an invitation to an email address. The administrator selects the person’s initial role (for example, Viewer, Developer, or Administrator).
   - The invited person receives an email containing a one‑time registration link bound to the tenant.
   - The invited person clicks the link, verifies their email, sets a password, and finishes registration.
   - The account is created in the tenant with the selected role. Multi‑factor authentication can be required by policy.

2. Self‑service sign‑up (optional, per tenant)
   - A tenant can allow self‑registration under constraints (for example, only email domains on an allow list or an invite code).
   - A new person visits the sign‑up page, enters their email, verifies it, and sets a password.
   - The account starts in Pending state until an administrator approves it or is auto‑approved based on tenant policy. Rate limiting and anti‑automation checks (for example, Completely Automated Public Turing test to tell Computers and Humans Apart (CAPTCHA)) may be enabled.

3. External Single Sign‑On (SSO) via an external Identity Provider (IdP) (optional, per tenant)
   - A tenant administrator connects an external Identity Provider such as Google, Microsoft, GitHub, or a corporate OpenID Connect provider.
   - A new person clicks “Continue with <provider>” on the sign‑in page.
   - On the first successful sign‑in, the platform creates a local account for that person in the tenant (just‑in‑time provisioning) and assigns a default role. Administrators can change the role later. Passwords for external providers are never stored by the platform.

Notes
- Email verification is required for all new accounts.
- Administrators can revoke invitations, disable accounts, or reset roles at any time.

---

## 2) How people sign in to tenant applications

A person can sign in with either email and password (on the platform’s sign‑in page) or via an external Identity Provider connected by the tenant.

Supported application types and sign‑in flows:

- Web applications (including the Dashboard)
  - Use OpenID Connect Authorization Code flow with Proof Key for Code Exchange (PKCE).
  - Typical steps: the application redirects the browser to /connect/authorize, the person authenticates and gives consent, then the application exchanges the returned authorization code for tokens.
  - Backend For Frontend (BFF) pattern is recommended: tokens are stored on the server and the browser holds only a secure session cookie.

- Mobile and desktop applications
  - Use the same OpenID Connect Authorization Code flow with Proof Key for Code Exchange (PKCE) via a native Software Development Kit (SDK).
  - Store the refresh token securely (for example, operating‑system secrets store). Rotate refresh tokens as configured by the server.
  - Optional: Device Code flow for devices without an embedded browser.

- Social sign‑in
  - When a tenant has an external Identity Provider attached, the person can choose “Continue with <provider>”. The flow completes as above, and the account is matched or provisioned in the tenant.

Important
- The Resource Owner Password Credentials grant (direct username/password to the token endpoint) is disabled in production. People always authenticate via the hosted sign‑in page or an external Identity Provider.

---

## 3) Tenant context and switching tenants

- Tokens issued after sign‑in include a tenant identifier claim (tenant_id). The Gateway copies this value into the X‑Tenant‑Id request header when it is not already present.
- If a person belongs to multiple tenants, the application can offer a tenant selector. Switching tenants may require a fresh sign‑in so that the new token carries the correct tenant identifier.

---

## 4) Service‑to‑service calls (for completeness)

- Application backends and jobs authenticate with Client Credentials (client identifier and client secret). These tokens do not represent a person and do not carry roles unless you model service accounts explicitly.
- When using Client Credentials, the caller must include the X‑Tenant‑Id header. The Gateway validates the audience and requires a tenant header for protected routes.

---

## 5) Security and privacy defaults

- Email verification is enforced; Multi‑Factor Authentication (MFA) can be required by tenant policy.
- Access tokens are short‑lived. Refresh tokens are longer‑lived and can be rotated with reuse detection when enabled by the server.
- Sessions can be revoked by an administrator; sign‑out invalidates the browser session. External Identity Provider passwords are never stored by the platform.
- Roles follow least privilege. Administrators should grant the minimal role needed and review access regularly.

---

## 6) Troubleshooting

- “Forbidden” when accessing administrator routes: your token does not include the Administrator role for this tenant. Ask a tenant administrator to adjust your role.
- “Missing tenant” error: the X‑Tenant‑Id header is not present, and the token did not include a tenant identifier. Sign in again and select the correct tenant, or ensure the client sets X‑Tenant‑Id.
- “Token expired”: refresh your session (the application should refresh automatically) or sign in again.
- “Account not found” with an external Identity Provider: ask a tenant administrator to enable the provider for this tenant or to invite you by email.

---

## Dictionary

- OpenID Connect (OIDC): An identity layer on top of the OAuth 2.0 protocol used for single sign‑on and token issuance.
- Proof Key for Code Exchange (PKCE): An extension to the OpenID Connect Authorization Code flow that protects against code interception.
- Backend For Frontend (BFF): A pattern where the web application’s backend holds tokens and issues a session cookie to the browser.
- Single Sign‑On (SSO): A method that allows a person to use one identity to access multiple applications.
- Identity Provider (IdP): A service that authenticates a person (for example, Google, Microsoft, GitHub) and issues identity assertions to relying applications.
- Software Development Kit (SDK): A set of tools and libraries that helps applications integrate with a platform.
- JSON Web Token (JWT): A compact, signed token format used to convey claims such as subject, roles, and tenant.
- Role‑Based Access Control (RBAC): An authorization model where permissions are assigned to roles (for example, Administrator), and roles are assigned to users.
- Client Credentials: An OAuth 2.0 flow for server‑to‑server calls using an application’s own credentials.
- Multi‑Factor Authentication (MFA): A security mechanism requiring more than one method of authentication (for example, password and code).
- Completely Automated Public Turing test to tell Computers and Humans Apart (CAPTCHA): A challenge‑response test used to determine whether a user is human.
