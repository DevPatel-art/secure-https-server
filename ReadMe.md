Secure HTTPS Backend – Phase 1 (Node + Express)

## Setup Instructions
Requirements
Node.js 
Windows (Command Prompt, GitBash or PowerShell)

Clone and Install
git clone <?> secure-https-server
npm install (install dependencies)

Generate SSL Certificates
OpenSSL (self-signed)

winget install -e --id ShiningLight.OpenSSL.Light
mkdir cert
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout cert/private-key.pem -out cert/certificate.pem -days 365 \
  -subj "/C=CA/ST=Alberta/L=Calgary/O=SecureServer/OU=WebSec/CN=localhost"
  This will create the 2 certificates in cert folder

Run the Server
npm run dev   # uses nodemon
# or
npm start


Visit:
http://localhost:3000 http server
https://localhost:3001 https server

Test different routes: (for cache control)
/, /posts, /posts/b1, /profile, /healthz, /docs/security

## SSL Configuration

I used a self-signed SSL certificate created with OpenSSL for local development.
This means I generated my own certificate and private key just to encrypt data on my local computer. It’s not trusted by browsers, which is why you might see a warning but it still provides real encryption for testing.

Integration in the code:

const httpsOptions = {
  key: fs.readFileSync("cert/private-key.pem"),
  cert: fs.readFileSync("cert/certificate.pem"),
};
https.createServer(httpsOptions, app).listen(3001);

Why: Self-signed/mkcert is fast to use and easy to test locally.

## Essential HTTP Headers

Configured with Helmet:

app.use(helmet());
app.use(helmet.frameguard({ action: "deny" }));
if (process.env.NODE_ENV === "production") {
  app.use(helmet.hsts({ maxAge: 15552000, includeSubDomains: true }));
}
app.use(helmet.contentSecurityPolicy({
  useDefaults: true,
  directives: {
    "default-src": ["'self'"],
    "script-src": ["'self'"],
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'", "data:"],
    "connect-src": ["'self'"],
    "object-src": ["'none'"],
    "frame-ancestors": ["'none'"],
  },
}));


Header purposes:

CSP limits scripts → prevents XSS.
HSTS forces HTTPS.
X-Frame-Options (DENY) blocks clickjacking.
X-Content-Type-Options (nosniff) stops MIME sniffing.
Referrer-Policy protects URL data (Helmet default).

⚙️ Routes & Caching (Part D)
Route	Purpose	Cache-Control	Security Note
/	Home	public, max-age=60, stale-while-revalidate=30	Non-sensitive
/posts	List posts	public, max-age=300, stale-while-revalidate=60	Non-sensitive
/posts/:id	Post detail	public, max-age=300, stale-while-revalidate=60	Validate IDs
/profile	User data	no-store	Contains PII → never cache
/healthz	Server status	no-store	Always fresh
/docs/security	Security info	public, max-age=120, stale-while-revalidate=30	Non-sensitive

Verification:
https://localhost:3001/posts --insecure
https://localhost:3001/profile --insecure

Shows cached vs non-cached policies.

## Lessons Learned

I learned how to create SSL certificates and set up a secure HTTPS server using Node and Express.
I also learned how to use Cache-Control for different pages like /posts, /profile, and /docs/security to control what gets cached and what doesn’t.
Additionally, I learned how to add security headers using Helmet to protect the website from common attacks and make it more secure.
This project helped me understand how to combine security and improve performance when building a backend server.


### Phase 2
Secure HTTPS Backend — Phase 2: Authentication & Authorization

# Overview
In this phase, I implemented a secure authentication and authorization system for the HTTPS backend built in Phase 1.
The focus was on integrating local (email + password) and Google OAuth 2.0 SSO authentication, secure sessions, role-based access control (RBAC), JWT tokens, and CSRF protection.
The goal was to create a backend that balances security + usability and protects sensitive user data.

# Setup Instructions
Prerequisites
Node.js (v18 or higher)
npm
OpenSSL (certificates from Phase 1)

1. Clone Repository & Install Dependencies
git clone https://github.com/DevPatel-art/secure-https-server.git
cd secure-https-server
npm install

2. Environment Variables (.env)

Create a .env file in the project root:

PORT=3001
GOOGLE_CLIENT_ID=your_google_client_id_here
GOOGLE_CLIENT_SECRET=your_google_client_secret_here
GOOGLE_REDIRECT_URL=https://localhost:3001/auth/google/callback
JWT_ACCESS_SECRET=my_access_secret
JWT_REFRESH_SECRET=my_refresh_secret

3. Run Server
npm run dev


Then open:

 https://localhost:3001 (secure server)
 http://localhost:3000 → redirects to HTTPS

 Authentication Mechanisms
 1. Local Authentication (email + password)
Implemented using bcryptjs for password hashing.
POST /auth/local/signup — register new users.
POST /auth/local/login — verifies credentials & creates a secure session.
Session IDs stored in signed cookies using express-session.

 2. Google OAuth 2.0 (SSO)
Implemented with passport-google-oauth20.
Users can log in with Google and a profile is created automatically.
/auth/google → Google login page
/auth/google/callback → returns profile and creates session

 3. JWT (Token-Based Login)
Used for API-only access and mobile clients.
POST /auth/jwt/login → issues access + refresh tokens.
Access token valid 15 minutes; refresh token 7 days.
POST /auth/jwt/refresh → refreshes access token when expired.
POST /auth/jwt/logout → clears cookies and invalidates tokens.
Tokens stored in secure HTTP-only cookies.

 4. Session Management & Security
Implemented via express-session with these settings:
cookie: {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  maxAge: 7 * 24 * 60 * 60 * 1000,
}

Prevents cross-site scripting (XSS) access to cookies.
Session IDs regenerated on login to avoid fixation attacks.

 5. CSRF Protection
Implemented with csurf and cookie-parser.
GET /csrf-token → returns token for frontend to include in subsequent POST requests.
Requests without a valid token are rejected (ForbiddenError: invalid csrf token).

# Role-Based Access Control (RBAC)
Two roles: User and Admin.
Default users sign up as User.
Admin promotion via:
POST https://localhost:3001/auth/make-admin
Protected routes verify roles through middleware.
Example:
/api/secret — JWT-protected route for authenticated users.
/auth/make-admin — only accessible to logged-in users with valid sessions.

 Testing Steps
 Local Login Flow
POST /auth/local/signup → register user.
POST /auth/local/login → returns session cookie.
Access /auth/me → verify user info.

✅ Google Login Flow
Visit https://localhost:3001/auth/google.
Select Google account → redirects to /auth/login-success.
JSON response shows user profile.

✅ JWT Login Flow
POST /auth/jwt/login → returns access_token & refresh_token cookies.
GET /api/secret → requires JWT token.
POST /auth/jwt/refresh → refreshes expired access token.
POST /auth/jwt/logout → removes tokens.

✅ RBAC Test
POST /auth/make-admin → promotes logged-in user to Admin.
Verify in response: "role": "Admin".

✅ Security Tests
Attempt POST without CSRF token → should return 403.
Attempt requests with expired JWT → should return 401.

🧠 Lessons Learned
I learned how to:
Build a secure authentication system using Passport.js and Google OAuth 2.0.
Implement password hashing with bcrypt to protect user data.
Manage secure sessions with cookies that use HttpOnly, Secure, and SameSite.
Create and validate JWTs with refresh tokens to maintain session continuity.
Apply CSRF protection and rate-limiting to defend against common web attacks.
Use RBAC to limit sensitive access based on roles.
This phase strengthened my understanding of backend security and how to combine multiple layers of protection in a Node.js Express server.

### Phase 3
 Secure User Profile Dashboard

This phase focused on implementing advanced security controls to protect user profile data, including validation, sanitization, output encoding, encryption, dependency management, and vulnerability testing. A secure dashboard was created where authenticated users can view and update their personal information.

 1. Dashboard Features
The dashboard is located at:
https://localhost:3001/dashboard

 Features Implemented
Displays user-specific data (name, email, bio)
Retrieves data using secure 
Logout button ends session 
Responsive UI built with HTML/CSS
User profile update form with strict validation
Fully protected from XSS and malicious inputs

Security Highlights
No user-generated content is rendered using innerHTML
All inserted values use .textContent
Sensitive fields are decrypted on load and re-encrypted on update

 2. Input Validation Implementation

Input validation is done using express-validator inside routes/profile.js.

Validation Rules
Field	Validation Rules	Attack Prevented
Name	3–50 characters, letters + spaces only
Email	Must follow standard email format
Bio	Max 500 characters, letters/numbers/basic punctuation only

Examples of "Evil Inputs" Tested

<script>alert(1)</script>	Rejected	Validation 400 — blocked
<img src=x onerror=alert(1)>	Rejected	Blocked by regex
' OR '1'='1	Rejected	Blocked (name only letters allowed)
1000 characters spam	Rejected	Fails max-length rule

Why This Works
No HTML tags allowed in any field
No dangerous characters allowed
Bio uses a strict whitelist (not blacklist)
Requests return detailed validation errors

 3. Output Encoding Implementation 
To prevent reflected or stored XSS, all outputs are escaped.

Techniques Used
escape-html 
const safeName = escapeHtml(user.name || "");
textContent 
document.getElementById("userName").textContent = data.name;

Why This Prevents XSS
<script> becomes harmless text instead of usable code
Even if strange input entered DB (it won’t), it would still be escaped
No innerHTML is used anywhere

Example
User input:
<script>alert("XSS")</script>

Displayed on dashboard as:
&lt;script&gt;alert("XSS")&lt;/script&gt;

No browser execution hence safe.

 4. Encryption of Sensitive Data 

All sensitive data is encrypted before storage and decrypted only on use.

 Encryption Algorithm 
AES-256-GCM using:
32-byte key from .env
Random 12-byte IV
Authentication tag for integrity
Encryption Format:
iv:tag:ciphertext  (all Base64)
Fields Encrypted:
encrypted_email
encrypted_bio

In Transit Encryption (HTTPS)
The entire application, including profile updates, runs over:
https://localhost:3001
ensuring TLS transport security.

Example Stored Values (secure)
encrypted_email: ClVdXG0JYvI=:alwe8gJkl302...==
encrypted_bio: 29Hc4LvdFfc=:JLkd1vR93qwE...==

 5. Third-Party Dependency Management
Dependency Management Practices
npm audit performed
Found vulnerabilities
Fixed using:
npm audit fix
Screenshot documented separately

Automates:
Installing dependencies
Running tests
Running security audits (npm audit)
Weekly scheduled checks
.gitignore includes:
node_modules
.env
SSL certificates
Editor/system files

Why This Matters
Protects against known exploits in outdated packages
Automates maintenance
Reduces human error

 6. Cloning & Running Instructions

Step 1: Clone Repo
git clone https://github.com/DevPatel-art/secure-https-server.git
cd secure-https-server

Step 2: Install Dependencies
npm install

Step 3: Add .env
SESSION_SECRET=your-secret
PROFILE_ENC_KEY=32-character-random-string
GOOGLE_CLIENT_ID=xxxx
GOOGLE_CLIENT_SECRET=xxxx

Step 4: Add SSL certificates

Place your keys into:
cert/private-key.pem
cert/certificate.pem

Step 5: Start HTTPS server
npm run dev

Step 6: Visit the dashboard
https://localhost:3001/dashboard

🧪 7. Dependency Management Documentation

This project uses:
express-validator
escape-html
Security lifecycle:
Audit regularly (npm audit)


Never commit node_modules or .env
Keep dependencies minimal to reduce attack surface

📝 8. Lessons Learned 
Understanding Input Validation

I learned how important strict validation rules are for security.
Name, email, and bio each require different constraints, and using a approach which ensures safety.

Preventing XSS with Output Encoding
Even if input validation missed something, using .textContent and escape-html ensures nothing can execute in the browser.

Correct Use of Encryption
Implementing AES-256-GCM helped me understand:
IV generation
Authentication tags
Why encryption must be at rest AND in transit

Dependency Security
Running npm audit and GitHub Actions showed me how vulnerabilities can appear even in trusted packages.
Debugging & Problem Solving
