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
        <a className="app__brand" href="#/check">
          Job Scam Checker
        </a>
        <nav className="app__nav">
          {(Object.keys(ROUTES) as Route[]).map((key) => (
            <a
              key={key}
              href={`#/${key}`}
              className={
                "app__nav-link" + (route === key ? " app__nav-link--active" : "")
              }
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
