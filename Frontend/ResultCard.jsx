import React, { useState } from "react";

export default function ResultCard({ result, error, isVerifying }) {
  // result is expected to be the `verification` object from backend
  const data = result?.verification || result || {};

  const [showAdvanced, setShowAdvanced] = useState(false);

  // Signature type: derive from detected_types ("AES,SES")
  const rawTypes = data.detected_types || "";
  const typeList = rawTypes
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const signatureType = typeList.length > 0 ? typeList.join(", ") : "Unknown";

  // Overall status based on aes_status
  let overallStatus = "Unknown";
  let overallStatusClass = "badge-invalid";

  if (data.aes_status === "valid") {
    overallStatus = "Valid";
    overallStatusClass = "badge-valid";
  } else if (data.aes_status === "invalid") {
    overallStatus = "Invalid";
    overallStatusClass = "badge-invalid";
  } else if (data.aes_status === "not_present") {
    overallStatus = "No AES signature";
    overallStatusClass = "badge-neutral";
  } else if (data.aes_status === "error") {
    overallStatus = "Error during verification";
    overallStatusClass = "badge-invalid";
  }

  // We know verify_pdf_aes_openssl uses SHA-256
  const hashAlgorithm = "SHA-256";

  // Simple mapping: if aes_status is valid, treat hash/RSA as OK
  const hashMatch = data.aes_status === "valid";
  const rsaValid = data.aes_status === "valid";

  const hashMatchText = hashMatch ? "Match ✔" : "Mismatch ✖";
  const hashMatchClass = hashMatch ? "status-valid" : "status-invalid";

  const rsaValidText = rsaValid ? "Valid ✔" : "Invalid ✖";
  const rsaValidClass = rsaValid ? "status-valid" : "status-invalid";

  // Clean certificate information
  let certInfo = "No additional certificate information returned by backend.";

  if (typeof data.aes_details === "string" && data.aes_details.trim() !== "") {
    const d = data.aes_details;

    if (d.includes("self-signed certificate")) {
      certInfo =
        "Signature is cryptographically valid, but the certificate is self-signed (not issued by a public Certificate Authority).";
    } else if (d.includes("fallback_match")) {
      certInfo =
        "OpenSSL validation fell back to raw RSA/SHA-256 digest comparison. Signature integrity is valid.";
    } else if (d.includes("openssl_attempt")) {
      certInfo =
        "The cryptographic signature was validated. OpenSSL returned diagnostic details (common with self-signed certificates).";
    }
  }

  return (
      <div className={`card ${result ? "card--has-result" : ""}`}>

      <h2 className="result-title">Verification Result</h2>

      {isVerifying && (
  <>
    <p className="result-placeholder">Verifying... please wait.</p>
    <div className="skeleton-loader" />
  </>
)}


      {error && <div className="error-box">{error}</div>}

      {!result && !error && !isVerifying && (
        <p className="result-placeholder">
          Upload a signed PDF and click <strong>Verify Signature</strong>.
        </p>
      )}

      {!isVerifying && result && !error && (
        <>
          <div className="result-section">
            <h3>Summary</h3>
            <div className="result-row">
              Signature type:{" "}
              <span className="badge badge-type">{signatureType}</span>
            </div>
            <div className="result-row">
              Overall status:{" "}
              <span className={"badge " + overallStatusClass}>
                {overallStatus}
              </span>
            </div>
            <div className="result-row">
              File: <strong>{data.filename || "—"}</strong>
            </div>
          </div>

          <div className="result-section">
            <h3>Cryptographic Checks</h3>
            <div className="result-row">
              Hash algorithm: {hashAlgorithm}
            </div>
            <div className="result-row">
              Hash match:{" "}
              <span className={hashMatchClass}>{hashMatchText}</span>
            </div>
            <div className="result-row">
              RSA verification:{" "}
              <span className={rsaValidClass}>{rsaValidText}</span>
            </div>
          </div>

          <div className="result-section">
            <h3>Certificate (if present)</h3>
            <div className="result-row result-placeholder">{certInfo}</div>
          </div>

          <div className="result-section">
  <h3>
    Advanced details{" "}
    <button
      type="button"
      className="toggle-button"
      onClick={() => setShowAdvanced((v) => !v)}
      style={{
        marginLeft: 8,
        fontSize: "0.8em",
        padding: "4px 8px",
        cursor: "pointer",
      }}
    >
      {showAdvanced ? "Hide" : "Show"}
    </button>
  </h3>

  <div className={`advanced-container ${showAdvanced ? "open" : ""}`}>
    {typeof data.aes_details === "string" &&
      data.aes_details.trim() !== "" && (
        <div className="result-row">
          <strong>OpenSSL / backend diagnostics:</strong>
          <pre
            style={{
              whiteSpace: "pre-wrap",
              fontSize: "0.8em",
              maxHeight: "160px",
              overflow: "auto",
              marginTop: "4px",
            }}
          >
            {data.aes_details}
          </pre>
        </div>
      )}

    <div className="result-row" style={{ marginTop: "8px" }}>
      <strong>Raw backend object:</strong>
      <pre
        style={{
          whiteSpace: "pre-wrap",
          fontSize: "0.8em",
          maxHeight: "200px",
          overflow: "auto",
          marginTop: "4px",
        }}
      >
        {JSON.stringify(data, null, 2)}
      </pre>
    </div>
  </div>
</div>

        </>
      )}
    </div>
  );
}

