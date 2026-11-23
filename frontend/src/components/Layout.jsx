import Sidebar from "./shell/Sidebar.jsx";
import TopBar from "./shell/TopBar.jsx";

export default function Layout({ children }) {
  return (
    <div className="app">
      <a className="skip-link" href="#content">Skip to content</a>
      <Sidebar />
      <div className="main">
        <TopBar />
        <main className="content" id="content" tabIndex={-1}>{children}</main>
      </div>
    </div>
  );
}
