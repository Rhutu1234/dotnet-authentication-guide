# Authentication in ASP.NET Core

*A deep-dive walkthrough of authentication in ASP.NET Core — covering the `ClaimsPrincipal`/`ClaimsIdentity` model everything else builds on, authentication schemes and handlers as the core abstraction, cookie authentication for browser-based apps, JWT bearer authentication for APIs, the genuine distinction between OAuth 2.0 and OpenID Connect (routinely confused, and worth getting precisely right), multi-scheme applications, and how authentication actually integrates with the middleware and authorization systems covered elsewhere in this series.*

---

## Table of Contents

1. [Introduction](#introduction)
2. [ClaimsPrincipal and ClaimsIdentity: The Model Everything Builds On](#1-claimsprincipal-and-claimsidentity-the-model-everything-builds-on)
3. [Authentication Schemes: The Core Abstraction](#2-authentication-schemes-the-core-abstraction)
4. [How the Authentication Middleware Actually Works](#3-how-the-authentication-middleware-actually-works)
5. [Cookie Authentication](#4-cookie-authentication)
6. [JWT Bearer Authentication](#5-jwt-bearer-authentication)
7. [OAuth 2.0: What It Actually Is (and Isn't)](#6-oauth-20-what-it-actually-is-and-isnt)
8. [OpenID Connect: Authentication Built on Top of OAuth](#7-openid-connect-authentication-built-on-top-of-oauth)
9. [OAuth/OIDC vs. JWT: Three Layers That Get Conflated](#8-oauthoidc-vs-jwt-three-layers-that-get-conflated)
10. [Multiple Schemes in One Application](#9-multiple-schemes-in-one-application)
11. [Token Validation Parameters in Depth](#10-token-validation-parameters-in-depth)
12. [Refresh Tokens and Token Expiration](#11-refresh-tokens-and-token-expiration)
13. [Authentication vs. Authorization, Precisely](#12-authentication-vs-authorization-precisely)
14. [Common Pitfalls](#13-common-pitfalls)
15. [Quick Reference Table](#quick-reference-table)
16. [Conclusion](#conclusion)

---

## Introduction

Authentication answers exactly one question — "who is making this request?" — and ASP.NET Core answers it through a genuinely pluggable, scheme-based system: the same `HttpContext.User` property gets populated whether the caller presented a session cookie, a JWT bearer token, or something else entirely, because every authentication mechanism in ASP.NET Core ultimately produces the same output shape (a `ClaimsPrincipal`) through the same middleware hook this series' Middleware guide's Section 10 introduces. This guide goes deep on that scheme-based model, the two most common concrete mechanisms (cookies for browser apps, JWT bearer tokens for APIs), and — because it's one of the most persistently confused topics in web development — the precise, correct distinction between OAuth 2.0 (an authorization delegation protocol) and OpenID Connect (an authentication protocol built on top of it), which are related but genuinely not the same thing.

```plaintext
Request arrives with SOME credential (a cookie, a bearer token, ...) →
  Authentication middleware asks the configured SCHEME's HANDLER:
  "can you make sense of this credential?" →
  Handler validates it, and if valid, builds a ClaimsPrincipal →
  HttpContext.User is populated →
  Authorization middleware (this series' Filters guide) later checks
  THIS SAME ClaimsPrincipal against whatever access rules apply
```

---

## 1. ClaimsPrincipal and ClaimsIdentity: The Model Everything Builds On

### A claim: a single piece of asserted information about a user

```csharp
var claim = new Claim(ClaimTypes.Email, "alice@example.com");
// a claim is just a TYPE ("email") and a VALUE ("alice@example.com") — one asserted fact
```

Every fact ASP.NET Core's identity model represents about a user — their name, email, roles, a unique identifier — is expressed as a `Claim`: a simple type/value pair. This is deliberately generic and extensible; there's no fixed schema of "a user has exactly these fields" — a user is represented by however many claims a given authentication mechanism chooses to assert about them.

### `ClaimsIdentity`: one specific, authenticated identity, made up of a set of claims

```csharp
var identity = new ClaimsIdentity(new[]
{
    new Claim(ClaimTypes.NameIdentifier, "user-123"),
    new Claim(ClaimTypes.Email, "alice@example.com"),
    new Claim(ClaimTypes.Role, "Admin")
}, authenticationType: "Cookies"); // the authenticationType names WHICH mechanism produced this identity
```

A `ClaimsIdentity` bundles a set of claims together as one coherent identity, tagged with the authentication type that established it — this `authenticationType` string matters directly for Section 2's scheme model, since it's what later code can use to determine *how* a given identity was established, not just *what* it claims.

### `ClaimsPrincipal`: the user as a whole — potentially made up of MULTIPLE identities

```csharp
var principal = new ClaimsPrincipal(identity); // the common case — ONE identity

// HttpContext.User IS a ClaimsPrincipal
bool isAdmin = context.User.IsInRole("Admin");
string? email = context.User.FindFirst(ClaimTypes.Email)?.Value;
```

`HttpContext.User` is a `ClaimsPrincipal` — worth knowing it can, in principle, wrap *multiple* `ClaimsIdentity` objects at once (relevant when Section 9's multi-scheme scenarios genuinely combine several authenticated identities for one request), though the overwhelmingly common case is exactly one identity per principal. `IsInRole` and `FindFirst` are the standard, everyday ways application code reads claims back out, entirely independent of which authentication scheme originally produced them.

---

## 2. Authentication Schemes: The Core Abstraction

### A scheme is a named configuration of a specific authentication mechanism

```csharp
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = "Cookies"; // WHICH scheme handles "who is this" by default
    options.DefaultChallengeScheme = "Cookies";      // WHICH scheme handles "please authenticate" by default
})
.AddCookie("Cookies", options => { /* cookie-specific configuration */ })
.AddJwtBearer("Bearer", options => { /* JWT-specific configuration */ });
```

`AddAuthentication` establishes the overall authentication system, and each `.Add...()` call registers a distinct, named **scheme** — a specific combination of a *handler* (the code that knows how to extract and validate a particular kind of credential) and its configuration. The string names ("Cookies", "Bearer") are entirely your choice; what matters is that each scheme has its own handler and its own configuration, and different parts of your application can target different schemes explicitly (Section 9).

### `IAuthenticationHandler`: what a scheme actually is, underneath

```plaintext
Every scheme is backed by a handler implementing (conceptually)
  IAuthenticationHandler — with the job of: given the current request,
  can you find a credential this scheme understands, and if so, is it
  VALID? If valid, produce a ClaimsPrincipal (Section 1). If not, or if
  no credential is present at all, report failure or "no result."
```

This is the pluggable core the entire system is built around — a cookie handler looks for a specific cookie and validates its encrypted contents; a JWT bearer handler looks for an `Authorization: Bearer <token>` header and validates the token's signature and claims (Section 5); a custom handler could look for an API key header, or anything else — the framework doesn't care *how* a scheme identifies a caller, only that it can produce a `ClaimsPrincipal` (or report that it couldn't).

### Authenticate, Challenge, and Forbid: the three operations a scheme supports

```plaintext
Authenticate: "who does THIS request's credential say the caller is?"
  — the operation the authentication MIDDLEWARE performs automatically
  on every request (Section 3).
Challenge: "this caller needs to authenticate, but hasn't (or their
  credential wasn't valid) — tell them how" — for cookie auth, this
  typically means a REDIRECT to a login page; for JWT bearer auth, it
  typically means a 401 response with a WWW-Authenticate header.
Forbid: "this caller IS authenticated, but isn't ALLOWED to do this" —
  distinct from Challenge; this is what happens when authorization
  (not authentication) fails, per Section 12's precise distinction.
```

Worth knowing these three named operations exist explicitly, because they explain *why* the same failure (a 401 vs. a redirect to login) looks so different depending on which scheme is involved — each scheme defines its own behavior for Challenge and Forbid, appropriate to the kind of client it's meant to serve (a browser expects a redirect; an API client expects a status code).

---

## 3. How the Authentication Middleware Actually Works

### `UseAuthentication()` is genuinely just middleware, running exactly where this series' Middleware guide says it should

```csharp
app.UseAuthentication(); // per this series' Middleware guide's Section 10 — runs the CURRENT scheme's Authenticate
```

This series' Middleware guide's Section 10 already establishes that authentication middleware's job is purely to *identify* the caller, populating `HttpContext.User`, without itself rejecting anything — this section goes one level deeper into exactly what that middleware does mechanically: for each request, it invokes the configured default scheme's handler's `AuthenticateAsync()`, and if that succeeds, sets `HttpContext.User` to the resulting `ClaimsPrincipal`; if it fails (no credential present, or an invalid one), `HttpContext.User` is left as an unauthenticated, anonymous principal — and, critically, **the request still proceeds**. The middleware does not short-circuit here; rejecting unauthenticated requests is authorization's job (Section 12), not authentication's.

### Why this matters: an endpoint can genuinely choose to allow anonymous access

```csharp
[AllowAnonymous] // explicitly opts OUT of any authorization requirement — the endpoint runs even if User is anonymous
public IActionResult PublicEndpoint() => Ok("Anyone can see this");
```

Because authentication middleware never rejects a request on its own, an endpoint with no `[Authorize]` requirement at all (or one explicitly marked `[AllowAnonymous]`) runs perfectly normally even for a completely unauthenticated caller — `HttpContext.User` is simply an anonymous principal in that case, and the endpoint's own logic decides what, if anything, to do with that fact.

---

## 4. Cookie Authentication

### The standard mechanism for browser-based, session-style applications

```csharp
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";       // where to redirect on Challenge
        options.AccessDeniedPath = "/Account/Denied"; // where to redirect on Forbid
        options.ExpireTimeSpan = TimeSpan.FromHours(1);
        options.SlidingExpiration = true; // the cookie's expiry resets on activity, rather than being fixed
    });
```

Cookie authentication is genuinely simple in concept: after a successful login, the server issues an encrypted, tamper-proof cookie containing the user's claims; on every subsequent request, the cookie handler decrypts and validates that cookie, reconstructing the `ClaimsPrincipal` without needing to hit a database or any external service at all — the cookie itself *is* the credential, self-contained and cryptographically protected.

### Signing a user in: constructing the identity and issuing the cookie

```csharp
public async Task<IActionResult> Login(LoginRequest request)
{
    if (!await ValidateCredentialsAsync(request.Username, request.Password))
        return Unauthorized();

    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, request.Username),
        new Claim(ClaimTypes.Role, "User")
    };
    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var principal = new ClaimsPrincipal(identity);

    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal); // ISSUES the cookie
    return Ok();
}
```

`SignInAsync` is the operation that actually creates and attaches the authentication cookie to the response — this is genuinely the *only* place a cookie-authenticated identity is established; every subsequent request's `HttpContext.User` comes from the cookie handler decrypting this cookie, not from re-running any login logic.

### Why cookie authentication is stateful (or, more precisely, self-contained-but-server-issued) and cookie-dependent

```plaintext
Cookies are automatically sent by BROWSERS on every request to the
  issuing domain — this makes cookie auth a natural fit for traditional,
  server-rendered web applications, but a poor fit for APIs consumed by
  non-browser clients (mobile apps, server-to-server calls), which is
  precisely why JWT bearer authentication (Section 5) exists as the
  standard alternative for that different class of client.
```

---

## 5. JWT Bearer Authentication

### The standard mechanism for APIs, where the client explicitly attaches a token to every request

```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "https://my-auth-server.com",
            ValidateAudience = true,
            ValidAudience = "my-api",
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey))
        };
    });
```

Unlike cookies, a JWT (JSON Web Token) isn't automatically attached by the client's platform — the calling application (a mobile app, a single-page app, another server) explicitly includes it in an `Authorization: Bearer <token>` header on every request that needs authentication. `Section 10` covers `TokenValidationParameters` in full depth; worth introducing here as the core configuration determining exactly what makes a presented token acceptable.

### What a JWT actually contains, structurally

```plaintext
A JWT has three Base64Url-encoded, dot-separated parts:
  HEADER.PAYLOAD.SIGNATURE

Header: metadata about the token itself (which signing algorithm was used).
Payload: the CLAIMS (Section 1) — issuer, audience, expiration, and
  whatever else the issuer chose to include, e.g. user ID, roles.
Signature: a cryptographic signature over the header and payload,
  computed using a key ONLY the issuer (and anyone the issuer trusts)
  possesses — this is what makes the token TAMPER-EVIDENT: any
  modification to the header or payload invalidates the signature.
```

This is worth understanding precisely, since it directly explains the JWT bearer handler's actual job: decode the payload (trivial — it's just Base64, not encrypted, so its contents are *readable* by anyone, just not *forgeable*), then verify the signature against the configured signing key, and check the claims (issuer, audience, expiration) against the configured `TokenValidationParameters` — if all of that checks out, the payload's claims become the `ClaimsPrincipal`.

### The critical distinction: a JWT is readable but not writable, without the signing key

```plaintext
Because the payload is only Base64-ENCODED, not encrypted, ANYONE who
  intercepts a JWT can read its claims directly — this is NOT a secrecy
  mechanism. What it DOES guarantee is that nobody without the private
  signing key can create a NEW, valid token or MODIFY an existing one
  without the signature check failing.
```

This is a genuinely common point of confusion worth stating explicitly: don't put anything genuinely secret (a password, a raw credit card number) directly into a JWT's claims, since the payload is trivially decodable by inspection — the security guarantee a JWT provides is *integrity* (you can trust the claims weren't tampered with, if the signature validates) and *authenticity* (you can trust they came from whoever holds the signing key), not confidentiality.

---

## 6. OAuth 2.0: What It Actually Is (and Isn't)

### OAuth 2.0 is an AUTHORIZATION DELEGATION protocol — not, by itself, an authentication protocol

```plaintext
OAuth 2.0's core problem statement: "Application A wants to access
  SOME OF a user's data or capabilities on Service B, WITHOUT the user
  giving Application A their Service B password directly."

Example: a photo-printing app wanting read access to your Google Photos,
  without you ever typing your Google password into the photo-printing app.
```

This is worth stating as precisely and plainly as possible, because it's the single most commonly mis-stated fact in this whole topic area: OAuth 2.0 was designed to solve **delegated authorization** — "can Application A do X on my behalf, on Service B" — not "who is this user." Using raw OAuth 2.0 alone to figure out *who* a user is (which many applications historically did, incorrectly, by treating "I got a valid access token" as proof of identity) is a well-documented anti-pattern that OpenID Connect (Section 7) exists specifically to correct.

### The OAuth 2.0 roles and flow, concretely

```plaintext
Resource Owner: the USER, who owns the data/capability being accessed.
Client: the APPLICATION requesting access (the photo-printing app).
Authorization Server: issues ACCESS TOKENS after the user grants consent
  (Google's own auth server, in the example above).
Resource Server: the API that actually holds the protected data, and
  which accepts the access token as proof of authorized access
  (Google Photos' API itself).

Flow: Client redirects the user to the Authorization Server → user logs
  in (to the AUTHORIZATION SERVER, not the client) and consents →
  Authorization Server redirects back to the Client with an
  AUTHORIZATION CODE → Client exchanges that code for an ACCESS TOKEN →
  Client uses the access token to call the Resource Server.
```

An OAuth 2.0 access token's entire purpose is proving "the bearer of this token is authorized to perform these specific actions" — it says nothing, by design, about the identity of the person who granted that authorization, which is exactly the gap Section 7 covers.

---

## 7. OpenID Connect: Authentication Built on Top of OAuth

### OIDC adds exactly one thing OAuth 2.0 doesn't provide: a standardized way to establish identity

```plaintext
OpenID Connect (OIDC) is a THIN IDENTITY LAYER built directly on top of
  OAuth 2.0's flows — it adds a new, standardized token type (the ID
  TOKEN, itself a JWT, per Section 5) and a standardized way to request
  and receive basic profile information about the AUTHENTICATED user,
  turning "I have a token authorizing some access" into "I know WHO
  this specific person is."
```

This is the precise fix for Section 6's gap: where OAuth 2.0 alone only produces an access token (proving authorization), OIDC layers on an **ID token** — a JWT specifically containing claims about the authenticated user's identity (their subject identifier, email, name, and similar) — issued alongside the access token, using essentially the same underlying OAuth flow.

### The `scope=openid` signal: how a client asks for OIDC's identity layer specifically

```csharp
builder.Services.AddAuthentication(options =>
{
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie() // OIDC still typically pairs with a LOCAL cookie, to maintain the app's own session after login
.AddOpenIdConnect(options =>
{
    options.Authority = "https://my-identity-provider.com";
    options.ClientId = "my-app";
    options.ClientSecret = "...";
    options.ResponseType = "code";
    options.Scope.Add("openid"); // THIS is what specifically requests an ID TOKEN, the OIDC-specific piece
    options.Scope.Add("profile");
});
```

Including `openid` in the requested scopes is the literal, protocol-level signal that distinguishes "I just want an OAuth access token for some API" from "I want OIDC's identity layer too" — this is precisely why the scope's name gives the whole standard its name, and why an application genuinely needing to know *who* a user is (not just what they're authorized to do) must specifically request it.

### Why this distinction is worth getting exactly right, not just "close enough"

```plaintext
A well-known, real-world class of security vulnerability arose from
  applications using a raw OAuth 2.0 access token as a stand-in for
  identity verification — because an access token's audience and purpose
  is SPECIFIC TO THE RESOURCE SERVER IT WAS ISSUED FOR, a token obtained
  for ONE purpose could sometimes be misused to "prove identity" to an
  entirely DIFFERENT, unintended relying party, since OAuth alone never
  defined a standard, safe way to use an access token for that purpose
  at all. OpenID Connect's ID token exists specifically to close this gap
  with a token TYPE and validation model actually designed for identity verification.
```

This is worth knowing as the concrete, historical reason the OAuth-vs-OIDC distinction isn't pedantry — treating "the user completed an OAuth flow and I got a token back" as equivalent to "I've verified who this user is" is a genuine, documented security anti-pattern, and OIDC's explicit ID token (with its own, purpose-built claims and validation rules) is the standards-based fix.

---

## 8. OAuth/OIDC vs. JWT: Three Layers That Get Conflated

### JWT is a TOKEN FORMAT — it says nothing about the protocol that produced or uses it

```plaintext
JWT (Section 5): a way to encode a set of claims, signed for integrity —
  a FORMAT, nothing more. It doesn't inherently know or care whether it's
  being used as an OAuth access token, an OIDC ID token, or something
  else entirely (a cookie's contents, an internal service-to-service
  token with no relation to OAuth/OIDC at all).
OAuth 2.0 (Section 6): a PROTOCOL for delegated authorization. Its
  access tokens are OFTEN, but not NECESSARILY, JWTs — the OAuth spec
  itself doesn't mandate any particular token format.
OpenID Connect (Section 7): a PROTOCOL, built on OAuth, specifically
  for authentication. Its ID tokens ARE always JWTs, by the OIDC spec itself.
```

This three-way distinction is genuinely worth holding precisely in mind, since "JWT authentication" as a casual phrase conflates a token *format* with the *protocol* that issued and governs it — an application can validate JWTs (Section 5's mechanics) that came from an OIDC-compliant ID token, from a bespoke OAuth access token, or from an entirely custom, in-house token-issuing service with no OAuth/OIDC involvement whatsoever; the validation code looks nearly identical in all three cases, but what the token actually *represents* and *guarantees* differs substantially between them.

---

## 9. Multiple Schemes in One Application

### A single application can support both cookie and JWT bearer authentication simultaneously

```csharp
builder.Services.AddAuthentication()
    .AddCookie("Cookies", options => { /* ... */ })
    .AddJwtBearer("Bearer", options => { /* ... */ });
```

A genuinely common real-world shape: a web application serving both its own browser-based UI (cookie auth) and an API consumed by mobile clients or third parties (JWT bearer auth) — both schemes are registered, each with its own name, and each request is authenticated against whichever scheme is actually relevant to it.

### Targeting a specific scheme per endpoint, rather than relying on one global default

```csharp
[Authorize(AuthenticationSchemes = "Bearer")] // this endpoint ONLY accepts JWT bearer tokens
public IActionResult ApiEndpoint() => Ok();

[Authorize(AuthenticationSchemes = "Cookies")] // this endpoint ONLY accepts the cookie
public IActionResult WebEndpoint() => Ok();
```

`[Authorize(AuthenticationSchemes = "...")]`, applied per controller or action, is how a multi-scheme application controls exactly which credential type each endpoint accepts — this series' Filters guide's Section 3 covers `[Authorize]` as an authorization filter in general; worth knowing here that its `AuthenticationSchemes` property is precisely how it interacts with this guide's scheme model, restricting which scheme(s) are consulted for that specific endpoint's authentication check.

### Policy schemes: dynamically selecting a scheme based on the request itself

```csharp
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "Smart";
})
.AddPolicyScheme("Smart", "Smart", options =>
{
    options.ForwardDefaultSelector = context =>
        context.Request.Headers.ContainsKey("Authorization") ? "Bearer" : "Cookies"; // pick based on the REQUEST
});
```

For applications that would rather not require every single endpoint to be explicitly annotated with a specific scheme, a policy scheme lets you write logic that inspects the incoming request and forwards to the appropriate underlying scheme automatically — genuinely useful when the same set of endpoints might reasonably be called by either a browser (cookie) or an API client (bearer token) and you'd rather not duplicate every route.

---

## 10. Token Validation Parameters in Depth

### Each validation flag closes a specific, real attack surface — worth understanding individually, not just copying as boilerplate

```csharp
new TokenValidationParameters
{
    ValidateIssuer = true,        // is this token from an issuer I actually TRUST?
    ValidIssuer = "https://my-auth-server.com",
    ValidateAudience = true,      // was this token ISSUED FOR ME specifically, or for some OTHER service?
    ValidAudience = "my-api",
    ValidateLifetime = true,      // has this token EXPIRED?
    ValidateIssuerSigningKey = true, // is the SIGNATURE genuinely valid, per the trusted key?
    IssuerSigningKey = mySigningKey,
    ClockSkew = TimeSpan.FromMinutes(2) // a small tolerance for clock drift between servers
};
```

### Why `ValidateAudience` specifically matters, and what skipping it risks

```plaintext
Without audience validation, a token issued by a TRUSTED issuer, but
  intended for a DIFFERENT service (a different "audience"), would still
  be accepted here — this is precisely the class of token-misuse concern
  Section 7 raised in the OAuth-vs-OIDC discussion: a token's validity
  is not just about WHO signed it, but WHAT it was specifically issued FOR.
```

This is worth calling out specifically because it's a genuinely easy validation step to accidentally disable or misconfigure, and doing so reopens exactly the cross-service token confusion that OIDC's ID token model, and correct audience validation generally, are designed to prevent — a token that's perfectly validly signed by a trusted issuer is still the wrong token to accept if it wasn't issued *for this specific API*.

### `ClockSkew`'s default is more generous than most developers expect

```plaintext
The DEFAULT ClockSkew is 5 MINUTES, not zero — meaning a token that
  technically expired up to 5 minutes ago (per its own `exp` claim) is
  still accepted, to tolerate minor clock drift between the token issuer's
  server and the validating server's own clock.
```

Worth knowing this explicitly, since it's a genuinely common source of confusion when testing token expiration behavior — a token that "should have" expired can still validate successfully for up to 5 minutes past its stated expiration by default, which is intentional, deliberate tolerance for real-world clock drift, not a bug in the validation logic.

---

## 11. Refresh Tokens and Token Expiration

### Why access tokens are deliberately short-lived

```plaintext
An access token, once issued, generally CANNOT be revoked before its own
  expiration — there's no built-in, universal "undo" for a JWT that's
  already been handed out, short of maintaining a server-side revocation
  list (which reintroduces exactly the STATEFUL lookup JWTs were meant
  to avoid). Short expiration times (minutes, not days) BOUND the damage
  a leaked or stolen token can do.
```

This is the concrete security reasoning behind why access tokens are typically configured to expire quickly — a stolen token that's only valid for 15 minutes is a meaningfully smaller risk than one valid for a week, precisely because there's no cheap, universal way to invalidate a self-contained, signature-verified token before it naturally expires.

### Refresh tokens: exchanging a longer-lived, more carefully-protected token for a fresh access token

```plaintext
A REFRESH token is issued alongside the access token, but is typically
  longer-lived and, critically, is only ever sent to the AUTHORIZATION
  SERVER (never to arbitrary resource servers/APIs) to request a NEW
  access token once the current one expires — this lets a client stay
  "logged in" for an extended period without the SHORT-LIVED access
  token's exposure window ever growing.
```

This pattern reconciles Section 11's short-expiration security goal with the practical need for a good, uninterrupted user experience — the access token stays short-lived and low-risk, while the refresh token (which never touches the resource server directly, and is typically stored more carefully) is what actually enables a long-lived session, refreshed transparently in the background as needed.

---

## 12. Authentication vs. Authorization, Precisely

### This series' Middleware guide's Section 10 already establishes the plain-language distinction — worth restating with this guide's full depth behind it

```plaintext
Authentication (this ENTIRE guide): populates HttpContext.User with a
  ClaimsPrincipal — establishes WHO the caller is (or that they're
  anonymous), via whatever scheme's handler successfully validated
  their credential.
Authorization (this series' Filters guide's Section 3): consults THAT
  SAME ClaimsPrincipal against a specific endpoint's requirements
  ([Authorize(Roles = "Admin")], a policy, etc.) — decides WHETHER this
  specific, now-known caller is ALLOWED to do this specific thing.
```

Everything this guide covers — schemes, handlers, cookies, JWTs, OAuth, OIDC — exists entirely in service of correctly, securely populating that one property, `HttpContext.User`. Authorization, covered in this series' Middleware guide's Section 10 and Filters guide's Section 3, is a genuinely separate concern that consumes this guide's output but never overlaps with it — a request can be perfectly, successfully authenticated (the system knows exactly who's asking) and still be entirely unauthorized for what it's trying to do.

---

## 13. Common Pitfalls

| Pitfall | Why it hurts | Better approach |
|---|---|---|
| Treating a raw OAuth 2.0 access token as proof of user identity | OAuth access tokens prove authorized access to a resource, not identity — a well-documented, real security anti-pattern | Use OpenID Connect's ID token specifically when identity verification is the actual goal (Sections 6-7) |
| Putting genuinely secret data directly into a JWT's claims | JWT payloads are Base64-encoded, not encrypted — readable by anyone who intercepts the token | Only include claims that are safe to be publicly readable; use the token's signature for integrity, not the payload for confidentiality (Section 5) |
| Disabling or misconfiguring `ValidateAudience` | Accepts tokens that were validly issued, but for an entirely different, unintended service | Always validate audience against the specific expected value for your API (Section 10) |
| Assuming `HttpContext.User` is null or throws for an unauthenticated request | Authentication middleware never rejects requests — it populates an anonymous principal, and the request proceeds normally | Check `context.User.Identity?.IsAuthenticated` explicitly; rely on authorization (not authentication) to actually reject requests (Section 3, Section 12) |
| Confusing "JWT authentication" with "OAuth" or "OIDC" as if they're the same thing | JWT is a token format; OAuth and OIDC are protocols that may or may not use JWTs — conflating them leads to incorrect assumptions about what a token actually guarantees | Keep the three layers distinct: format (JWT), authorization protocol (OAuth), authentication protocol (OIDC) (Section 8) |
| Issuing long-lived access tokens for convenience | A leaked long-lived token remains a live risk for its entire validity window, with no cheap way to revoke it | Keep access tokens short-lived; use a refresh token for maintaining a longer session securely (Section 11) |
| Applying `[Authorize]` without specifying `AuthenticationSchemes` in a multi-scheme application | The default scheme may not be the one the specific endpoint's clients actually use, causing unexpected authentication failures | Explicitly specify which scheme(s) an endpoint accepts when more than one is registered (Section 9) |
| Assuming cookie authentication works for non-browser API clients | Cookies are a browser-specific transport mechanism; other clients (mobile apps, server-to-server calls) don't automatically attach or manage them | Use JWT bearer (or another explicit-token scheme) for clients that aren't browsers (Section 4-5) |

---

## Quick Reference Table

| Concept | Purpose |
|---|---|
| `ClaimsPrincipal`/`ClaimsIdentity` | The universal identity model — a set of claims, regardless of which scheme produced them |
| Authentication scheme | A named handler + configuration pair (Cookies, Bearer, etc.), pluggable and independently configurable |
| `UseAuthentication()` | Middleware that populates `HttpContext.User`; never itself rejects a request |
| Cookie authentication | Self-contained, encrypted credential automatically sent by browsers — standard for server-rendered web apps |
| JWT bearer authentication | Explicit, client-attached token — standard for APIs and non-browser clients |
| OAuth 2.0 | A protocol for delegated AUTHORIZATION ("can this app act on my behalf here") — not, by itself, identity verification |
| OpenID Connect | An identity layer built on OAuth, adding the ID token specifically for AUTHENTICATION |
| `TokenValidationParameters` | Governs exactly what makes a presented JWT acceptable — issuer, audience, lifetime, signature |
| Refresh token | A longer-lived, more carefully-scoped token used to obtain fresh, short-lived access tokens |

---

## Conclusion

Authentication in ASP.NET Core is built around one deliberately simple, pluggable idea — a scheme's handler takes whatever credential a request presents and, if it validates, produces a `ClaimsPrincipal` — and every mechanism this guide covers, from a self-contained encrypted cookie to a cryptographically signed JWT arriving through a full OpenID Connect flow, exists purely to answer that one question correctly and securely. The OAuth-versus-OIDC distinction this guide spends real effort getting precisely right isn't pedantry: treating an authorization protocol as if it were an authentication protocol is a genuine, documented, historically real security mistake, and understanding that OAuth proves *authorized access* while OIDC's ID token specifically proves *identity* is what separates a correctly-designed authentication system from one that merely happens to work in the common case until it's tested against a scenario the underlying protocol was never designed to cover.

Everything this guide covers feeds into exactly one place — `HttpContext.User` — which is precisely where this series' Filters guide's authorization discussion picks up: authentication and authorization are genuinely separate systems, connected by that single shared property, and understanding authentication deeply is what makes the authorization layer's own guarantees actually trustworthy, rather than resting on an identity model you've merely assumed is correctly established underneath it.

---

*Found this useful? Feel free to star the repo, open an issue with corrections, or share the accepted-a-token-issued-for-a-different-service incident that made audience validation, and the OAuth-versus-OIDC distinction generally, click far better than any protocol diagram ever could.*
