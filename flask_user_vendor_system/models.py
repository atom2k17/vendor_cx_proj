from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Vendor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    win_stories = db.Column(db.Text)
    tags = db.Column(db.Text)
    rating = db.Column(db.Float)

class UserRequirement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    requirement = db.Column(db.Text)
    tags = db.Column(db.Text)