import React from "react";

export default function Footer() {
  return (
    <footer className="footer">
      SigSecure • Digital Signature Verifier • {new Date().getFullYear()}
    </footer>
  );
}
