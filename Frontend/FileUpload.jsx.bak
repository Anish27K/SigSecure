import React, { useRef, useState } from "react";
import axios from "axios";

const BACKEND = "http://localhost:5001";

export default function FileUpload({
  setResult,
  setError,
  setIsVerifying,
  isVerifying,
}) {
  const inputRef = useRef(null);
  const [fileName, setFileName] = useState("");

  const handleSelect = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    if (!file.name.toLowerCase().endsWith(".pdf")) {
      setError("Only PDF files are allowed.");
      return;
    }

    window._sigsecureFile = file; // quick global stash
    setFileName(file.name);
    setError("");
  };

  const handleVerify = async () => {
    const file = window._sigsecureFile;
    if (!file) {
      setError("Please upload a PDF first.");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    setIsVerifying(true);
    setError("");
    setResult(null);

    try {
      const res = await axios.post(`${BACKEND}/verify`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setResult(res.data);
    } catch (err) {
      console.error(err);
      setError("Could not reach backend on http://localhost:5001/verify");
    }

    setIsVerifying(false);
  };

  return (
    <div>
      <div
        className="upload-box"
        onClick={() => inputRef.current && inputRef.current.click()}
      >
        <div>Click to upload a signed PDF</div>
        {fileName && (
          <div className="upload-filename">
            Selected: <strong>{fileName}</strong>
          </div>
        )}
        <input
          ref={inputRef}
          type="file"
          accept="application/pdf"
          className="hidden-input"
          style={{ display: "none" }}
          onChange={handleSelect}
        />
      </div>

      <button
        className="button-primary"
        onClick={handleVerify}
        disabled={isVerifying}
      >
        {isVerifying ? "Verifying..." : "Verify Signature"}
      </button>
    </div>
  );
}
