from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, Vendor, UserRequirement

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import pandas as pd

from config import Config

app = Flask(__name__)
app.config.from_object(Config)  
db = SQLAlchemy(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit():
    company_name = request.form['company_name']
    requirement = request.form['requirement']
    email = request.form['email']
    phone = request.form['phone']
    name = request.form['name']
    tags = request.form['tags']
    project_status = request.form.get('project_status', 'New')

    # Save user input
    user = UserRequirement(company_name=company_name, requirement=requirement, email=email, phone=phone, name=name, tags=tags, project_status=project_status) #tags=tags, 
    db.session.add(user)
    db.session.commit()

    return recommend_vendors(user)

def recommend_vendors(user):
    vendors = VendorProfile.query.all()

    if len(vendors) == 0:
        return render_template('recommend.html', user=user, vendors=[])

    elif len(vendors) == 1:
        # Only one vendor available, return it directly
        single_vendor = vendors[0]
        vendor_data = [{
            'id': single_vendor.id,
            'name': single_vendor.business_name,
            'win_stories': single_vendor.win_stories,
            'tags': single_vendor.tags,
            'rating': single_vendor.rating,
            'score': 1.0  # Perfect match by default
        }]
        return render_template('recommend.html', user=user, vendors=vendor_data)

    else:
        # Multiple vendors – use cosine similarity
        vendor_df = pd.DataFrame([{
            'id': v.id,
            'name': v.business_name,
            'combined': f"{v.win_stories} {v.tags}",
            'win_stories': v.win_stories,
            'tags': v.tags,
            'rating': v.rating
        } for v in vendors])

        user_text = f"{user.requirement} {user.tags}"

        tfidf = TfidfVectorizer(stop_words='english')
        vectors = tfidf.fit_transform([user_text] + vendor_df['combined'].tolist())
        similarity = cosine_similarity(vectors[0:1], vectors[1:]).flatten()

        vendor_df['score'] = similarity
        vendor_df.head(10)
        top_vendors = vendor_df.sort_values(by='score', ascending=False).head(3)

        return render_template('recommend.html', user=user, vendors=top_vendors.to_dict(orient='records'))


# MODELS
class AppUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20))
    first_login = db.Column(db.Boolean, default=True)
    full_profile = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('app_user.id'))
    profession = db.Column(db.String(100))
    skills = db.Column(db.Text)
    experience_level = db.Column(db.String(50))

    # New fields
    project_software = db.Column(db.String(200))  # e.g., "SolidWorks, ANSYS, MATLAB"
    service_type = db.Column(db.String(100))  # e.g., "CAD", "CAE", "Embedded", "PLA"
    phone = db.Column(db.String(20))

class VendorProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('app_user.id'))
    business_name = db.Column(db.String(100))
    win_stories = db.Column(db.Text)
    tags = db.Column(db.Text)
    rating = db.Column(db.Float)

class UserRequirement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    company_name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    requirement = db.Column(db.String(500))
    tags = db.Column(db.String(200))
    project_status = db.Column(db.String(100), default="New")

class Vendor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    win_stories = db.Column(db.Text)
    tags = db.Column(db.Text)
    rating = db.Column(db.Float)

# ROUTES

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = AppUser(
            username=request.form['username'],
            email=request.form['email']
        )
        user.set_password(request.form['password'])
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = AppUser.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            if user.first_login:
                return redirect(url_for('choose_role'))
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/choose-role', methods=['GET', 'POST'])
def choose_role():
    if request.method == 'POST':
        role = request.form['role']
        user = AppUser.query.get(session['user_id'])

        if role not in ['user', 'vendor', 'admin']:
            flash('Invalid role selected.')
            return redirect(url_for('choose_role'))

        user.role = role
        user.first_login = False
        db.session.commit()

        # Set session role after saving
        session['role'] = role

        return redirect(url_for('dashboard'))

    return render_template('choose_role.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session['role'] == 'user':
        return redirect(url_for('search_projects'))
    elif session['role'] == 'vendor':
        return redirect(url_for('vendor_market'))
    elif session['role'] == 'admin':
        return 'Admin dashboard coming soon!'
    return 'Invalid role.'

@app.route('/user/complete-profile', methods=['GET', 'POST'])
def user_complete_profile():
    if 'user_id' not in session or session['role'] != 'user':
        return redirect(url_for('login'))

    if request.method == 'POST':
        profile = UserProfile(
            user_id=session['user_id'],
            profession=request.form['Company name'],
            skills=request.form['Industry'],
            #experience_level=request.form['experience_level'],
            phone=request.form['phone'],
            project_software=request.form['project_software'],
            service_type=request.form['service_type']
        )
        db.session.add(profile)
        db.session.commit()

        user = AppUser.query.get(session['user_id'])
        user.full_profile = True
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template('user_profile.html')

@app.route('/vendor/complete-profile', methods=['GET', 'POST'])
def vendor_complete_profile():
    if 'user_id' not in session or session['role'] != 'vendor':
        return redirect(url_for('login'))

    if request.method == 'POST':
        profile = VendorProfile(
            user_id=session['user_id'],
            business_name=request.form['business_name'],
            win_stories=request.form['win_stories'],
            tags=request.form['tags'],
            rating=float(request.form['rating'])
        )
        db.session.add(profile)
        db.session.commit()

        user = AppUser.query.get(session['user_id'])
        user.full_profile = True
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template('vendor_profile.html')

@app.route('/vendor/market')
def vendor_market():
    if 'user_id' not in session or session['role'] != 'vendor':
        return redirect(url_for('login'))
    user_reqs = UserRequirement.query.order_by(UserRequirement.id.desc()).limit(20).all()
    return render_template('vendor_market.html', user_reqs=user_reqs)

@app.route('/search', methods=['GET', 'POST'])
def search_projects():
    if 'user_id' not in session or session['role'] != 'user':
        return redirect(url_for('login'))
    """
    keyword = request.args.get('keyword', '')
    rating = request.args.get('rating')

    query = Vendor.query
    if keyword:
        query = query.filter(Vendor.tags.ilike(f"%{keyword}%"))
    if rating:
        query = query.filter(Vendor.rating >= float(rating))

    results = query.all()
    return render_template('search.html', results=results)
    """
    if request.method == 'POST':
        name = session.get('username', 'User')
        requirement = request.form.get('requirement', '')
        tags = request.form.get('tags', '')

        # Create a temporary user-like object
        user = type('TempUser', (object,), {
            "name": name,
            "requirement": requirement,
            "tags": tags
        })()

        return recommend_vendors(user)

    return render_template('search.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)