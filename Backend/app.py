#!/usr/bin/env python3
import os
from flask import Flask, request, jsonify, current_app, send_from_directory
from werkzeug.utils import secure_filename
from config import Config
from models import db, Verification
from verify import detect_signature_type, verify_pdf_aes_openssl
from flask_cors import CORS


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Init DB + folders
    db.init_app(app)
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)

    CORS(app)  # allow all origins (frontend on 5173)

    # ---------------------------------------------------------
    # ✔ HEALTH CHECK
    # ---------------------------------------------------------
    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"}), 200

    # ---------------------------------------------------------
    # ✔ UPLOAD + VERIFY ENDPOINT (MAIN MODULE)
    # ---------------------------------------------------------
    @app.route("/api/upload", methods=["POST"])
    def upload():
        if "file" not in request.files:
            return jsonify({"error": "no file part"}), 400
        f = request.files["file"]
        if f.filename == "":
            return jsonify({"error": "no selected file"}), 400

        filename = secure_filename(f.filename)
        save_path = os.path.join(current_app.config["UPLOAD_DIR"], filename)
        f.save(save_path)

        # Detect signature type (AES, SES)
        detected = detect_signature_type(save_path)

        aes_status = "not_present"
        aes_details = ""
        if "AES" in detected:
            ca_path = os.path.join(
                current_app.config.get("CERTS_DIR", "./certs"),
                "ca-bundle.pem"
            )
            ca_bundle = ca_path if os.path.exists(ca_path) else None
            try:
                valid, details = verify_pdf_aes_openssl(save_path, ca_bundle=ca_bundle)
                aes_status = "valid" if valid else "invalid"
                aes_details = str(details)
            except Exception as e:
                aes_status = "error"
                aes_details = str(e)

        # Save to DB
        v = Verification(
            filename=filename,
            detected_types=",".join(detected),
            aes_status=aes_status,
            aes_details=aes_details
        )
        db.session.add(v)
        db.session.commit()

        v_refreshed = Verification.query.get(v.id)

        return jsonify(v_refreshed.to_dict()), 200

    # ---------------------------------------------------------
    # ✔ SERVE LOCAL UPLOAD HTML (OPTIONAL)
    # ---------------------------------------------------------
    @app.route("/upload", methods=["GET"])
    def serve_upload_page():
        return send_from_directory(
            os.path.dirname(os.path.abspath(__file__)),
            "upload.html"
        )

    # ---------------------------------------------------------
    # ⭐ NEW: HISTORY (LIST ALL RECORDS)
    # ---------------------------------------------------------
    @app.route("/api/history", methods=["GET"])
    def history():
        records = Verification.query.order_by(Verification.created_at.desc()).all()
        return jsonify([r.to_dict() for r in records]), 200

    # ---------------------------------------------------------
    # ⭐ NEW: FETCH SINGLE RECORD
    # ---------------------------------------------------------
    @app.route("/api/history/<int:vid>", methods=["GET"])
    def get_record(vid):
        record = Verification.query.get(vid)
        if not record:
            return jsonify({"error": "not found"}), 404
        return jsonify(record.to_dict()), 200

    # ---------------------------------------------------------
    # ⭐ NEW: DELETE A RECORD
    # ---------------------------------------------------------
    @app.route("/api/history/<int:vid>", methods=["DELETE"])
    def delete_record(vid):
        record = Verification.query.get(vid)
        if not record:
            return jsonify({"error": "not found"}), 404
        db.session.delete(record)
        db.session.commit()
        return jsonify({"deleted": vid}), 200

    return app


# ---------------------------------------------------------
# ✔ RUN APP DIRECTLY (DEV MODE)
# ---------------------------------------------------------
if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        db.create_all()      # create tables if missing
    app.run(host="0.0.0.0", port=5001, debug=True)

