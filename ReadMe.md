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