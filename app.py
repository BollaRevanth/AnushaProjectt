from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from forms import RegistrationForm, LoginForm, QuizForm, QuestionForm
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    questions = db.relationship('Question', backref='quiz', lazy=True)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    option1 = db.Column(db.String(200))
    option2 = db.Column(db.String(200))
    option3 = db.Column(db.String(200))
    option4 = db.Column(db.String(200))
    correct_option = db.Column(db.Integer)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)

# --- Auth Decorator ---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# --- Routes ---
@app.route('/')
def index():
    quizzes = Quiz.query.all()
    return render_template('index.html', quizzes=quizzes)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['user'] = user.id
            return redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route('/create_quiz', methods=['GET', 'POST'])
@login_required
def create_quiz():
    form = QuizForm()
    if form.validate_on_submit():
        new_quiz = Quiz(title=form.title.data, description=form.description.data)
        db.session.add(new_quiz)
        db.session.commit()
        return redirect(url_for('add_questions', quiz_id=new_quiz.id))
    return render_template('create_quiz.html', form=form)

@app.route('/quiz/<int:quiz_id>/add_question', methods=['GET', 'POST'])
@login_required
def add_questions(quiz_id):
    form = QuestionForm()
    if form.validate_on_submit():
        question = Question(
            text=form.text.data,
            option1=form.option1.data,
            option2=form.option2.data,
            option3=form.option3.data,
            option4=form.option4.data,
            correct_option=form.correct_option.data,
            quiz_id=quiz_id
        )
        db.session.add(question)
        db.session.commit()
        return redirect(url_for('add_questions', quiz_id=quiz_id))
    return render_template('add_question.html', form=form)

@app.route('/quiz/<int:quiz_id>/take')
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    return render_template('take_quiz.html', quiz=quiz)

@app.route('/submit_quiz', methods=['POST'])
def submit_quiz():
    score = 0
    total = 0
    for key, value in request.form.items():
        if key.startswith('q'):
            question_id = int(key[1:])
            selected = int(value)
            question = Question.query.get(question_id)
            if question and question.correct_option == selected:
                score += 1
            total += 1
    return render_template('result.html', score=score, total=total)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
