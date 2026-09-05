import { useEffect, useState } from "react";
import { CheckMessage } from "./views/CheckMessage";
import { VerifyRecruiter } from "./views/VerifyRecruiter";
import { Scammed } from "./views/Scammed";

type Route = "check" | "verify" | "scammed";

const ROUTES: Record<Route, { label: string; nav: string }> = {
  check: { label: "Check a message", nav: "Check a message" },
  verify: { label: "Verify a recruiter", nav: "Verify a recruiter" },
  scammed: { label: "I think I've been scammed", nav: "I've been scammed" },
};

function routeFromHash(): Route {
  const h = window.location.hash.replace(/^#\/?/, "");
  return h === "verify" || h === "scammed" ? h : "check";
}

export function App() {
  const [route, setRoute] = useState<Route>(routeFromHash);

  useEffect(() => {
    const onHash = () => setRoute(routeFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  return (
    <div className="app">
      <header className="app__header">
        <div className="app__brandbar">
          <a className="app__brand" href="#/check">
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path
                d="M12 2.5 4.5 5.6v5.5c0 4.6 3.2 8.9 7.5 10.4 4.3-1.5 7.5-5.8 7.5-10.4V5.6L12 2.5Z"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinejoin="round"
              />
              <path
                d="m8.9 11.8 2.1 2.1 4.1-4.1"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            Job Scam Checker
          </a>
          <span className="app__privacy">
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <rect
                x="4"
                y="10.5"
                width="16"
                height="10"
                rx="2"
                stroke="currentColor"
                strokeWidth="2"
              />
              <path
                d="M8 10.5V7.8a4 4 0 0 1 8 0v2.7"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
              />
            </svg>
            Runs in your browser — nothing is uploaded
          </span>
        </div>

        <nav className="app__nav">
          {(Object.keys(ROUTES) as Route[]).map((key) => (
            <a
              key={key}
              href={`#/${key}`}
              className={
                "app__nav-link" + (route === key ? " app__nav-link--active" : "")
              }
              aria-current={route === key ? "page" : undefined}
            >
              {ROUTES[key].nav}
            </a>
          ))}
        </nav>
      </header>

      <main className="app__main">
        {route === "check" && <CheckMessage />}
        {route === "verify" && <VerifyRecruiter />}
        {route === "scammed" && <Scammed />}
      </main>

      <footer className="app__footer">
        <p>
          Analysis runs entirely in your browser. Nothing you paste here is
          uploaded or stored. This tool gives guidance, not a guarantee — always
          verify an employer through its official website.
        </p>
      </footer>
    </div>
  );
}
