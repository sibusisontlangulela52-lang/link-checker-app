import { useState, useEffect } from "react";
import { supabase } from "./supabaseClient";
import "./App.css";

const API_URL = import.meta.env.VITE_API_URL;

function App() {
  // ----- link checker state -----
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  // ----- auth state -----
  const [session, setSession] = useState(null);
  const [plan, setPlan] = useState("free");
  const [showAuth, setShowAuth] = useState(false);
  const [authMode, setAuthMode] = useState("login"); // "login" or "signup"
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [authMessage, setAuthMessage] = useState(null); // { type, text }
  const [authLoading, setAuthLoading] = useState(false);

  // Keep the session in sync (page refresh, login, logout, token refresh)
  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => setSession(data.session));

    const { data: listener } = supabase.auth.onAuthStateChange(
      (_event, newSession) => setSession(newSession)
    );

    return () => listener.subscription.unsubscribe();
  }, []);

  // Load the user's plan whenever the session changes
  useEffect(() => {
    if (!session) {
      setPlan("free");
      return;
    }

    supabase
      .from("profiles")
      .select("plan")
      .eq("id", session.user.id)
      .single()
      .then(({ data }) => setPlan(data?.plan || "free"));
  }, [session]);

  const openAuth = (mode) => {
    setAuthMode(mode);
    setAuthMessage(null);
    setShowAuth(true);
  };

  const closeAuth = () => {
    setShowAuth(false);
    setAuthMessage(null);
    setPassword("");
  };

  const switchAuthMode = () => {
    setAuthMode(authMode === "login" ? "signup" : "login");
    setAuthMessage(null);
  };

  const handleAuth = async (e) => {
    e.preventDefault();
    setAuthMessage(null);

    if (!email.trim() || !password) {
      setAuthMessage({ type: "error", text: "Please enter your email and password." });
      return;
    }

    if (authMode === "signup" && password.length < 8) {
      setAuthMessage({ type: "error", text: "Your password must be at least 8 characters." });
      return;
    }

    setAuthLoading(true);

    try {
      if (authMode === "signup") {
        const { data, error } = await supabase.auth.signUp({
          email: email.trim(),
          password,
        });

        if (error) throw error;

        if (data.session) {
          // Email confirmation is switched off: user is logged in straight away
          closeAuth();
          setEmail("");
        } else {
          setAuthMessage({
            type: "success",
            text: "Account created! Check your email and click the confirmation link, then log in.",
          });
        }
      } else {
        const { error } = await supabase.auth.signInWithPassword({
          email: email.trim(),
          password,
        });

        if (error) throw error;

        closeAuth();
        setEmail("");
      }
    } catch (error) {
      setAuthMessage({ type: "error", text: error.message });
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogout = async () => {
    await supabase.auth.signOut();
    setResult(null);
  };

  // ----- link checking -----
  const checkLink = async (e) => {
    if (e) e.preventDefault();

    let cleanUrl = url.trim();

    if (!cleanUrl) {
      setResult({ url: "", risk: "Error", message: "Please enter a URL." });
      return;
    }

    if (!/^https?:\/\//i.test(cleanUrl)) {
      cleanUrl = "https://" + cleanUrl;
    }

    setLoading(true);
    setResult({
      url: cleanUrl,
      risk: "Checking...",
      message: "Your link is being analysed.",
    });

    try {
      // Send the login token (if any) so the backend knows who is asking
      const { data: sessionData } = await supabase.auth.getSession();
      const token = sessionData.session?.access_token;

      const headers = { "Content-Type": "application/json" };
      if (token) headers.Authorization = `Bearer ${token}`;

      const response = await fetch(API_URL, {
        method: "POST",
        headers,
        body: JSON.stringify({ url: cleanUrl }),
      });

      const data = await response.json();

      if (!response.ok) {
        setResult({
          url: cleanUrl,
          risk: "Error",
          message: data.error || "Something went wrong.",
        });
        return;
      }

      setResult(data);
    } catch (error) {
      setResult({
        url: cleanUrl,
        risk: "Error",
        message: "Could not connect to the LinkGuard backend.",
      });
    } finally {
      setLoading(false);
    }
  };

  const riskClass = result?.risk
    ? result.risk.toLowerCase().replace(/[^a-z]/g, "")
    : "";

  return (
    <div className="app">
      <nav className="navbar">
        <div className="logo">🛡️ LinkGuard</div>

        <div className="creator-info">
          <div className="creator-name">Compiled by Sibusiso Ntlangulela</div>

          <div className="creator-role">Aspiring Cyber Security Analyst</div>

          <div className="creator-contact">
            <a href="mailto:sibusisontlangulela52@gmail.com">
              sibusisontlangulela52@gmail.com
            </a>
          </div>
        </div>

        <div className="nav-links">
          <a href="#home">Home</a>
          <a href="#about">About</a>
        </div>

        <div className="nav-auth">
          {session ? (
            <>
              <span className="user-email">{session.user.email}</span>
              <span className={`plan-badge ${plan}`}>{plan}</span>
              <button className="nav-button" onClick={handleLogout}>
                Log out
              </button>
            </>
          ) : (
            <>
              <button className="nav-button" onClick={() => openAuth("login")}>
                Log in
              </button>
              <button className="nav-button solid" onClick={() => openAuth("signup")}>
                Sign up
              </button>
            </>
          )}
        </div>
      </nav>

      <main className="hero" id="home">
        <div className="hero-content">
          <p className="tagline">CYBERSECURITY LINK PROTECTION</p>

          <h1>
            Check a link before
            <span>you click it.</span>
          </h1>

          <p className="description">
            Analyse suspicious URLs and identify potential phishing, malicious
            and unsafe websites.
          </p>

          <form className="checker" onSubmit={checkLink}>
            <input
              type="text"
              placeholder="Enter a URL e.g. https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />

            <button type="submit" disabled={loading}>
              {loading ? "Checking..." : "Check Link"}
            </button>
          </form>

          {result && (
            <div className={`result ${riskClass}`}>
              <h2>Scan Result</h2>

              {result.url && (
                <p>
                  <strong>URL:</strong> {result.url}
                </p>
              )}

              <p>
                <strong>Status:</strong> {result.risk}
              </p>

              <p>{result.message}</p>
            </div>
          )}
        </div>
      </main>

      <section className="features">
        <div>
          <h3>🔍 URL Analysis</h3>
          <p>Analyse links for suspicious characteristics.</p>
        </div>

        <div>
          <h3>🛡️ Risk Detection</h3>
          <p>Identify potential phishing and malicious links.</p>
        </div>

        <div>
          <h3>📊 Risk Reports</h3>
          <p>Get an understandable security assessment.</p>
        </div>
      </section>

      <section className="about" id="about">
        <div className="about-inner">
          <p className="tagline">ABOUT LINKGUARD</p>

          <h2>Think before you click.</h2>

          <p className="about-text">
            Phishing links are one of the most common ways scammers steal
            passwords and money. LinkGuard is a cybersecurity project that helps
            everyday people spot the warning signs in a link before they open
            it.
          </p>

          <h3 className="about-heading">How it works</h3>

          <div className="steps">
            <div className="step">
              <span className="step-number">1</span>
              <h4>Paste a link</h4>
              <p>
                Copy any suspicious link and paste it into the checker. You
                never need to open it.
              </p>
            </div>

            <div className="step">
              <span className="step-number">2</span>
              <h4>We analyse it</h4>
              <p>
                LinkGuard inspects the web address itself for common warning
                signs used in scams.
              </p>
            </div>

            <div className="step">
              <span className="step-number">3</span>
              <h4>Get your result</h4>
              <p>
                You receive a risk level (Low, Medium or High) with a
                plain-English explanation of why.
              </p>
            </div>
          </div>

          <h3 className="about-heading">What LinkGuard looks for</h3>

          <ul className="checks-list">
            <li>Links that don't use HTTPS</li>
            <li>Addresses made of numbers (IP addresses) instead of a real domain name</li>
            <li>Unusual international characters that can imitate real websites</li>
            <li>Shortened links that hide the real destination</li>
            <li>Domain endings that are often abused in scams</li>
            <li>Words common in phishing, such as "verify", "login" or "claim"</li>
            <li>Very long addresses or too many subdomains</li>
          </ul>

          <h3 className="about-heading">Free and Premium</h3>

          <div className="plans">
            <div className="plan-card">
              <h4>Free</h4>
              <p className="plan-status">Available now</p>
              <ul>
                <li>Check any link</li>
                <li>See the risk level</li>
                <li>Understand why it was flagged</li>
              </ul>
            </div>

            <div className="plan-card coming-soon">
              <h4>
                Premium <span className="soon-badge">Coming soon</span>
              </h4>
              <p className="plan-status">Still being planned and built</p>
              <p>
                Premium is still being worked out. The idea is detailed,
                step-by-step guidance on what to do next when a link turns out
                to be suspicious. More details will be shared once it is ready.
              </p>
            </div>
          </div>

          <p className="disclaimer">
            LinkGuard checks the patterns in a web address. A Low result means
            nothing obvious was found, not that a link is guaranteed safe, so
            always stay careful with links from unknown senders.
          </p>
        </div>
      </section>

      <footer className="footer">
        <p>© 2026 LinkGuard</p>
        <p>Aspiring Cyber Security Analyst</p>
      </footer>

      {showAuth && (
        <div className="modal-backdrop" onClick={closeAuth}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <button className="modal-close" onClick={closeAuth} aria-label="Close">
              ×
            </button>

            <h2>{authMode === "login" ? "Welcome back" : "Create your account"}</h2>

            <form onSubmit={handleAuth}>
              <input
                type="email"
                placeholder="Email address"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
              />

              <input
                type="password"
                placeholder="Password (min. 8 characters)"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete={authMode === "login" ? "current-password" : "new-password"}
              />

              {authMessage && (
                <p className={`auth-message ${authMessage.type}`}>{authMessage.text}</p>
              )}

              <button type="submit" className="auth-submit" disabled={authLoading}>
                {authLoading
                  ? "Please wait..."
                  : authMode === "login"
                  ? "Log in"
                  : "Sign up"}
              </button>
            </form>

            <p className="auth-switch">
              {authMode === "login" ? "No account yet? " : "Already have an account? "}
              <button type="button" className="link-button" onClick={switchAuthMode}>
                {authMode === "login" ? "Sign up" : "Log in"}
              </button>
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
