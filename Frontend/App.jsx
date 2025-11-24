import React, { useState } from "react";
import Navbar from "./components/Navbar.jsx";
import FileUpload from "./components/FileUpload.jsx";
import ResultCard from "./components/ResultCard.jsx";
import Footer from "./components/Footer.jsx";
import "./index.css"
import Sidebar from "./components/Sidebar.jsx";
import History from "./components/History.jsx";




export default function App() {
  const [active, setActive] = useState("verify");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [isVerifying, setIsVerifying] = useState(false);

  return (
    <div className="app">
      <Navbar />

      <div className="app-layout">
  <Sidebar active={active} onNavigate={(id) => setActive(id)} />

  <main style={{ padding: 0 }}>
    {/* ROUTING BASED ON active STATE */}
    {active === "home" && (
      <div className="card">
        <h2>Welcome to SigSecure</h2>
        <p>Quick overview and shortcuts will appear here.</p>
      </div>
    )}

    {active === "verify" && (
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 420px",
          gap: 20,
        }}
      >
        <div>
          <FileUpload
            setResult={setResult}
            setError={setError}
            setIsVerifying={setIsVerifying}
          />
        </div>

        <div>
          <ResultCard
            result={result}
            error={error}
            isVerifying={isVerifying}
          />
        </div>
      </div>
    )}

    {active === "history" && <History />}


    {active === "settings" && (
      <div className="card">
        <h2>Settings</h2>
        <p>App preferences will appear here.</p>
      </div>
    )}

    <div style={{ marginTop: 20 }}>
      <Footer />
    </div>
  </main>
</div>


      <Footer />
    </div>
  );
}
