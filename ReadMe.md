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
