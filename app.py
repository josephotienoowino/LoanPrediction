import numpy as np
from flask import Flask, request, jsonify, render_template, url_for, redirect, session, flash
import pickle
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

password = 'my_password'
hashed_password = generate_password_hash(password)


app = Flask(__name__, template_folder='templates')
model = pickle.load(open('loan_predictionmodel.pkl', 'rb'))

@app.route('/')
def home():
    return render_template('home.html')

#===================================================initialisation of the app==============================
app = Flask(__name__, template_folder='/home/jose/Desktop/Diabetes System/templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'mysecretkey'
db = SQLAlchemy(app)

# initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

#=================================================database==============================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------=============================route for the app=====================
@app.route('/')
def home():
    return render_template('home.html')
@app.route('/about')
def about():
    return render_template('about.html')

# ===============================================signup===========================session
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists')
            return redirect(url_for('signup'))
        else:
            new_user = User(username=username, email=email,
                            password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully')
            return redirect(url_for('login'))
    return render_template('signup.html')
# -==================================================login session-------=========================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password')
            return redirect(url_for('login'))
    return render_template('login.html')
# ==================================================logout session======================================
@app.route('/logout')
def logout():
    session.clear()
    flash('You have logged out')
    return redirect(url_for('login'))

@app.route('/predict',methods=['POST'])
def predict():
    int_features = [int(x) for x in request.form.values()]
    final_features = np.array(int_features).reshape(1, -1) # reshape to match model's input shape
    prediction = model.predict(final_features)

    output = round(prediction[0], 2)

    return render_template('home.html', prediction_text='Eligible for loan; {}'.format(output))

if __name__ == "__main__":
    app.run(debug=True)
