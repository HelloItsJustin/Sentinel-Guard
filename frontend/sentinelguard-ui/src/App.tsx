import { Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { useEffect, useMemo, useState } from "react";
import { WorkspacePage } from "./pages/Workspace";
import { DashboardPage } from "./pages/Dashboard";
import { PolicyPage } from "./pages/Policy";
import { ShieldIcon } from "./components/ShieldIcon";
import { Icon } from "./components/Icon";
import type { ChatSession } from "./types/chat";

type Theme = "light" | "dark";
const API_BASE_URL = import.meta.env.VITE_SENTINELGUARD_API_URL ?? "http://localhost:8000";

function createSession(now = Date.now()): ChatSession {
  return {
    id: `chat_${now}_${Math.random().toString(16).slice(2)}`,
    title: "New preflight",
    createdAt: now,
    updatedAt: now,
    messages: [
      {
        id: `sys_${now}`,
        role: "system",
        ts: now,
        text: "SentinelGuard is ready."
      }
    ]
  };
}

function formatChatTime(ts: number): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit"
  }).format(ts);
}

function getInitialTheme(): Theme {
  const stored = window.localStorage.getItem("sentinelguard-theme");
  if (stored === "dark" || stored === "light") return stored;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function App() {
  const navigate = useNavigate();
  const location = useLocation();
  const initial = useMemo(() => createSession(), []);
  const [sessions, setSessions] = useState<ChatSession[]>(() => [initial]);
  const [activeSessionId, setActiveSessionId] = useState<string>(() => initial.id);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [theme, setTheme] = useState<Theme>(() => getInitialTheme());

  const isDashboard = location.pathname.startsWith("/dashboard");
  const isPolicy = location.pathname.startsWith("/policy");
  const pageTitle = isDashboard ? "Incident Command" : isPolicy ? "Policy Center" : "AI Workspace";
  const activeSession = sessions.find((s) => s.id === activeSessionId) ?? sessions[0];
  const nextTheme = theme === "dark" ? "light" : "dark";

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    window.localStorage.setItem("sentinelguard-theme", theme);
  }, [theme]);

  function onNewChat() {
    const session = createSession();
    setSessions((prev) => [session, ...prev]);
    setActiveSessionId(session.id);
    navigate("/");
  }

  function selectChat(id: string) {
    setActiveSessionId(id);
    navigate("/");
  }

  function updateSession(sessionId: string, updater: (s: ChatSession) => ChatSession) {
    setSessions((prev) => prev.map((s) => (s.id === sessionId ? updater(s) : s)));
  }

  return (
    <div className="appShell">
      <aside className={sidebarCollapsed ? "sidebar collapsed" : "sidebar"} aria-label="SentinelGuard navigation">
        <div className="sidebarTop">
          <div className="brandRow">
            <button className="brandMarkButton" type="button" onClick={() => navigate("/")} aria-label="Open workspace">
              <span className="shieldMark">
                <ShieldIcon size={18} />
              </span>
              {!sidebarCollapsed ? (
                <span className="brandCopy">
                  <span className="brandName">SentinelGuard</span>
                  <span className="brandTag">AI Data Firewall</span>
                </span>
              ) : null}
            </button>
          </div>

          <button className="newChatButton" onClick={onNewChat} type="button" title="New preflight">
            <Icon name="plus" size={16} />
            {!sidebarCollapsed ? <span>New preflight</span> : null}
          </button>
        </div>

        <nav className="sideNav" aria-label="Primary">
          <button
            type="button"
            className={!isDashboard && !isPolicy ? "sideNavItem active" : "sideNavItem"}
            onClick={() => navigate("/")}
            title="AI Workspace"
          >
            <Icon name="message" size={17} />
            {!sidebarCollapsed ? <span>AI Workspace</span> : null}
          </button>
          <button
            type="button"
            className={isDashboard ? "sideNavItem active" : "sideNavItem"}
            onClick={() => navigate("/dashboard")}
            title="Incident Command"
          >
            <Icon name="dashboard" size={17} />
            {!sidebarCollapsed ? <span>Incident Command</span> : null}
          </button>
          <button
            type="button"
            className={isPolicy ? "sideNavItem active" : "sideNavItem"}
            onClick={() => navigate("/policy")}
            title="Policy Center"
          >
            <Icon name="panel" size={17} />
            {!sidebarCollapsed ? <span>Policy Center</span> : null}
          </button>
          <button
            type="button"
            className="sideNavItem"
            onClick={() => setSidebarCollapsed((v) => !v)}
            aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            <Icon name={sidebarCollapsed ? "chevronRight" : "chevronLeft"} size={17} />
            {!sidebarCollapsed ? <span>Collapse sidebar</span> : null}
          </button>
        </nav>

        {!sidebarCollapsed ? <div className="sidebarSectionTitle">Recent preflights</div> : null}
        <div className="conversationList">
          {sessions.map((s) => (
            <button
              key={s.id}
              type="button"
              className={s.id === activeSessionId && !isDashboard && !isPolicy ? "conversationItem active" : "conversationItem"}
              onClick={() => selectChat(s.id)}
              title={s.title}
            >
              <span className="conversationIcon">
                <Icon name="message" size={14} />
              </span>
              {!sidebarCollapsed ? (
                <span className="conversationCopy">
                  <span className="conversationTitle">{s.title}</span>
                  <span className="conversationMeta">{formatChatTime(s.updatedAt)}</span>
                </span>
              ) : null}
            </button>
          ))}
        </div>

        <div className="sidebarFooter">
          <span className="statusDot" />
          {!sidebarCollapsed ? (
            <span>
              Local API
              <strong>{API_BASE_URL.replace(/^https?:\/\//, "")}</strong>
            </span>
          ) : null}
        </div>
      </aside>

      <main className="mainArea">
        <header className="mainHeader">
          <div className="headerTitleBlock">
            <div className="headerEyebrow">
              <span className="statusDot" />
              Live policy pipeline
            </div>
            <h1 className="mainTitle">{pageTitle}</h1>
          </div>
          <div className="headerActions">
            <button
              className={!isDashboard && !isPolicy ? "routeButton active" : "routeButton"}
              type="button"
              onClick={() => navigate("/")}
            >
              <Icon name="message" size={16} />
              <span>Workspace</span>
            </button>
            <button
              className={isDashboard ? "routeButton active" : "routeButton"}
              type="button"
              onClick={() => navigate("/dashboard")}
            >
              <Icon name="dashboard" size={16} />
              <span>Dashboard</span>
            </button>
            <button
              className={isPolicy ? "routeButton active" : "routeButton"}
              type="button"
              onClick={() => navigate("/policy")}
            >
              <Icon name="panel" size={16} />
              <span>Policy</span>
            </button>
            <button
              className="themeToggle"
              type="button"
              onClick={() => setTheme(nextTheme)}
              aria-label={`Switch to ${nextTheme} mode`}
              title={`Switch to ${nextTheme} mode`}
            >
              <Icon name={theme === "dark" ? "sun" : "moon"} size={16} />
              <span>{theme === "dark" ? "Light" : "Dark"}</span>
            </button>
          </div>
        </header>

        <div className="mainContent">
          <Routes>
            <Route
              path="/"
              element={
                <WorkspacePage
                  session={activeSession}
                  updateSession={(updater) => updateSession(activeSession.id, updater)}
                />
              }
            />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/policy" element={<PolicyPage />} />
          </Routes>
        </div>
      </main>
    </div>
  );
}
