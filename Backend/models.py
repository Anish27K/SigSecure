from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Verification(db.Model):
    __tablename__ = "verifications"
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(512))
    detected_types = db.Column(db.String(256))
    aes_status = db.Column(db.String(64))
    aes_details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "detected_types": self.detected_types,
            "aes_status": self.aes_status,
            "aes_details": self.aes_details,
            "created_at": self.created_at.isoformat()
        }
