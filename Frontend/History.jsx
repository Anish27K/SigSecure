import React, { useEffect, useState } from "react";
import axios from "axios";

export default function History() {
  const [records, setRecords] = useState([]);

  const load = async () => {
    try {
      const res = await axios.get("/api/history");
      setRecords(res.data);
    } catch (err) {
      console.error(err);
    }
  };

  const remove = async (id) => {
    try {
      await axios.delete(`/api/history/${id}`);
      load();
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="card">
      <h2>Verification History</h2>

      <table className="history-table" style={{ width: "100%", marginTop: "16px" }}>
        <thead>
          <tr>
            <th>ID</th>
            <th>File</th>
            <th>Type(s)</th>
            <th>AES Status</th>
            <th>Date</th>
            <th></th>
          </tr>
        </thead>

        <tbody>
          {records.map((r) => (
            <tr key={r.id}>
              <td>{r.id}</td>
              <td>{r.filename}</td>
              <td>{r.detected_types}</td>
              <td>{r.aes_status}</td>
              <td>{new Date(r.created_at).toLocaleString()}</td>
              <td>
                <button
                  style={{
                    background: "red",
                    color: "white",
                    padding: "4px 8px",
                    borderRadius: "6px",
                    cursor: "pointer",
                  }}
                  onClick={() => remove(r.id)}
                >
                  Delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
