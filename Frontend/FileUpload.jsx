import React, { useRef, useState } from "react";
import axios from "axios";

const BACKEND = "/api";

export default function FileUpload({
  setResult,
  setError,
  setIsVerifying,
  isVerifying,
}) {
  const inputRef = useRef(null);
  const [fileName, setFileName] = useState("");
  const [fileMeta, setFileMeta] = useState(null);

  const handleSelect = (e) => {
  const file = e.target.files[0];
  if (!file) return;

  if (!file.name.toLowerCase().endsWith(".pdf")) {
    setError("Only PDF files are allowed.");
    return;
  }

  window._sigsecureFile = file; // quick global stash
  setFileName(file.name);
  setFileMeta({
    size: (file.size / 1024).toFixed(1) + " KB",
    time: new Date().toLocaleTimeString(),
  });
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
      const res = await axios.post(`${BACKEND}/upload`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      // debug: show exactly what backend returned
      console.log("API response (FileUpload):", res.data);

      // set the verification object if backend nested it, or use the root object
      setResult(res.data.verification || res.data);
    } catch (err) {
      console.error("Upload error (FileUpload):", err);
      setError("Could not reach backend on /api/upload");
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
    {fileMeta && (
      <div className="upload-meta">
        Size: {fileMeta.size} • Uploaded at: {fileMeta.time}
      </div>
    )}
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
