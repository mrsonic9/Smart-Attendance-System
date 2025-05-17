from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import os
import logging
import secrets
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(24)  # Secure random secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attendance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['FACE_LOG_FILE'] = 'face_logs.csv'
db = SQLAlchemy(app)

# Logging setup with rotation to prevent file size issues
logging.basicConfig(
    filename='system_logs.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Models
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(10), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    subjects = db.relationship('UserSubject', backref='user_ref', lazy=True)

class Subject(db.Model):
    __tablename__ = 'subject'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    users = db.relationship('UserSubject', backref='subject_ref', lazy=True)

class UserSubject(db.Model):
    __tablename__ = 'user_subject'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    role_in_subject = db.Column(db.String(20), nullable=False)
    __table_args__ = (
        db.UniqueConstraint('user_id', 'role_in_subject', name='unique_teacher_subject'),
    )

class LectureSchedule(db.Model):
    __tablename__ = 'lecture_schedule'
    id = db.Column(db.Integer, primary_key=True)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    min_attendance_duration = db.Column(db.Integer, nullable=False)
    subject = db.relationship('Subject', backref=db.backref('schedules', lazy=True))

class Attendance(db.Model):
    __tablename__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    entry_time = db.Column(db.DateTime, nullable=False)
    exit_time = db.Column(db.DateTime, nullable=True)
    duration = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(20), nullable=False)
    user = db.relationship('User', backref=db.backref('attendance_records', lazy=True))
    subject = db.relationship('Subject', backref=db.backref('attendance_records', lazy=True))

# CSRF Token Generation and Validation
@app.before_request
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
        logger.info(f"Generated new CSRF token: {session['csrf_token']}")
    if request.method == "POST":
        token = session.get('csrf_token')
        form_token = request.form.get('csrf_token')
        if not token or token != form_token:
            logger.warning(f"CSRF token mismatch: Session={token}, Form={form_token}, URL={request.url}")
            flash('Invalid CSRF token', 'error')
            return redirect(request.url)

# Helper Functions
def generate_user_id(role):
    """Generate a unique user ID based on role (e.g., ADMIN001, TEACH001, STUD001)."""
    prefix = {'admin': 'ADMIN', 'teacher': 'TEACH', 'student': 'STUD'}[role.lower()]
    last_user = User.query.filter_by(role=role.lower()).order_by(User.id.desc()).first()
    new_num = 1 if not last_user else int(last_user.user_id[5:]) + 1
    return f"{prefix}{new_num:03d}"

def archive_face_logs():
    """Archive the face log file with a timestamp."""
    log_file = app.config['FACE_LOG_FILE']
    if os.path.exists(log_file):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        archive_file = f"archive/face_logs_{timestamp}.csv"
        os.makedirs(os.path.dirname(archive_file), exist_ok=True)
        os.rename(log_file, archive_file)
        logger.info(f"Archived face logs to {archive_file}")

def sync_face_logs_to_db():
    """Sync face log entries from CSV to the database."""
    log_file = app.config['FACE_LOG_FILE']
    if not os.path.exists(log_file):
        logger.warning(f"Face log file {log_file} not found")
        return
    try:
        with open(log_file, newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader, None)  # Skip header if present
            for row in reader:
                if len(row) < 3:
                    logger.warning(f"Invalid row in face log: {row}")
                    continue
                user_id, timestamp_str, event_type = row[:3]
                try:
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    logger.warning(f"Invalid timestamp in face log: {timestamp_str}")
                    continue
                user = User.query.filter_by(user_id=user_id.strip()).first()
                if not user or user.role not in ['student', 'teacher']:
                    logger.warning(f"User not found or invalid role for face log entry: {user_id}")
                    continue
                user_subjects = UserSubject.query.filter_by(user_id=user.id).all()
                if not user_subjects:
                    logger.warning(f"No subjects assigned to user: {user_id}")
                    continue
                for user_subject in user_subjects:
                    subject_id = user_subject.subject_id
                    lecture = LectureSchedule.query.filter(
                        LectureSchedule.subject_id == subject_id,
                        LectureSchedule.start_time <= timestamp,
                        LectureSchedule.end_time >= timestamp
                    ).first()
                    if not lecture:
                        continue
                    attendance = Attendance.query.filter_by(
                        user_id=user.id,
                        subject_id=subject_id,
                        entry_time=timestamp
                    ).first()
                    if event_type == 'entry' and not attendance:
                        attendance = Attendance(
                            user_id=user.id,
                            subject_id=subject_id,
                            entry_time=timestamp,
                            status='pending'
                        )
                        db.session.add(attendance)
                    elif event_type == 'exit' and attendance and not attendance.exit_time:
                        attendance.exit_time = timestamp
                        duration = int((timestamp - attendance.entry_time).total_seconds())
                        attendance.duration = duration
                        attendance.status = 'pending' if duration >= lecture.min_attendance_duration else 'absent'
                    try:
                        db.session.commit()
                        logger.info(f"Synced face log for user {user_id}, event: {event_type}")
                    except Exception as e:
                        db.session.rollback()
                        logger.error(f"Error syncing face log for user {user_id}: {str(e)}")
    except (IOError, csv.Error) as e:
        logger.error(f"Error reading face log file: {str(e)}")

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        logger.info(f"Login attempt: Session CSRF token={session.get('csrf_token')}, Form CSRF token={request.form.get('csrf_token')}")
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        if not all([username, password, role]):
            flash('All fields are required', 'error')
            return redirect(url_for('login'))
        user = User.query.filter_by(username=username, role=role.lower()).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            logger.info(f"User logged in: {username}, role: {role}")
            return redirect(url_for('dashboard'))
        flash('Invalid credentials or role', 'error')
        logger.warning(f"Failed login attempt for username: {username}, role: {role}")
    return render_template('login.html', show_register=True, csrf_token=session.get('csrf_token', ''))

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    role = session.get('role')
    session.clear()
    logger.info(f"User logged out: ID {user_id}, role: {role}")
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        new_subject = request.form.get('new_subject')
        if not all([name, username, password, role]):
            flash('All fields are required', 'error')
            return redirect(url_for('register'))
        if role.lower() not in ['teacher', 'student']:
            flash('Invalid role selected', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            logger.warning(f"Registration failed: Username {username} already exists")
            return redirect(url_for('register'))
        user_id = generate_user_id(role.lower())
        user = User(
            user_id=user_id,
            name=name,
            username=username,
            password=generate_password_hash(password),
            role=role.lower()
        )
        db.session.add(user)
        new_subject_id = None
        if new_subject:
            existing_subject = Subject.query.filter_by(name=new_subject).first()
            if existing_subject:
                new_subject_id = existing_subject.id
            else:
                subject = Subject(name=new_subject)
                db.session.add(subject)
                db.session.flush()
                new_subject_id = subject.id
                logger.info(f"Added new subject: {new_subject}")
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'Error registering user: {str(e)}', 'error')
            logger.error(f"Error registering user {username}: {str(e)}")
            return redirect(url_for('register'))
        if role.lower() == 'teacher':
            subject_id = request.form.get('subject_id') or new_subject_id
            if subject_id:
                us = UserSubject(user_id=user.id, subject_id=subject_id, role_in_subject='teacher')
                db.session.add(us)
        elif role.lower() == 'student':
            subject_ids = request.form.getlist('subject_ids')
            if new_subject_id:
                subject_ids.append(str(new_subject_id))
            if subject_ids:
                for subject_id in subject_ids:
                    us = UserSubject(user_id=user.id, subject_id=subject_id, role_in_subject='student')
                    db.session.add(us)
        try:
            db.session.commit()
            logger.info(f"Registered user: {username}, role: {role}")
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error assigning subjects: {str(e)}', 'error')
            logger.error(f"Error assigning subjects for user {username}: {str(e)}")
            return redirect(url_for('register'))
    subjects = Subject.query.all()
    return render_template('register.html', subjects=subjects, csrf_token=session.get('csrf_token', ''))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    sync_face_logs_to_db()
    user = User.query.get(session['user_id'])
    if not user:
        logger.error("User not found in session")
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('login'))
    logger.info(f"Dashboard access for user: {user.username}, role: {user.role}, ID: {user.id}")
    try:
        if user.role == 'admin':
            users = User.query.all()
            subjects = Subject.query.all()
            schedules = LectureSchedule.query.all()
            logger.info(f"Admin dashboard loaded with {len(users)} users, {len(subjects)} subjects, {len(schedules)} schedules")
            return render_template('admin_dashboard.html', users=users, subjects=subjects, schedules=schedules)
        elif user.role == 'teacher':
            user_subject = UserSubject.query.filter_by(user_id=user.id, role_in_subject='teacher').first()
            if not user_subject:
                logger.warning(f"No subject assigned to teacher {user.username} (ID: {user.id})")
                flash('No subject assigned to this teacher. Please contact the admin.', 'error')
                return render_template('teacher_dashboard.html', subject=None, schedules=None, attendance=None, students=None, user=user)
            subject = user_subject.subject_ref
            if not subject:
                logger.warning(f"Subject not found for teacher {user.username} (ID: {user.id})")
                flash('Assigned subject not found. Please contact the admin.', 'error')
                return render_template('teacher_dashboard.html', subject=None, schedules=None, attendance=None, students=None, user=user)
            schedules = LectureSchedule.query.filter_by(subject_id=subject.id).all()
            students = User.query.join(UserSubject).filter(
                UserSubject.subject_id == subject.id,
                UserSubject.role_in_subject == 'student'
            ).all()
            attendance = Attendance.query.filter_by(subject_id=subject.id).all()
            logger.info(f"Teacher dashboard loaded for {user.username} with subject: {subject.name}, {len(schedules)} schedules, {len(attendance)} attendance records, {len(students)} students")
            return render_template('teacher_dashboard.html', subject=subject, schedules=schedules, attendance=attendance, students=students, user=user)
        else:  # student
            user_subjects = UserSubject.query.filter_by(user_id=user.id, role_in_subject='student').all()
            subjects = [us.subject_ref for us in user_subjects if us.subject_ref]
            attendance = Attendance.query.filter_by(user_id=user.id).all()
            if not subjects:
                logger.warning(f"No subjects assigned to student {user.username} (ID: {user.id})")
                flash('No subjects assigned to you. Please contact the admin.', 'error')
            logger.info(f"Student dashboard loaded for {user.username} with {len(subjects)} subjects, {len(attendance)} attendance records")
            return render_template('student_dashboard.html', user=user, subjects=subjects, attendance=attendance)
    except Exception as e:
        logger.error(f"Error loading dashboard for user {user.username}: {str(e)}")
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return redirect(url_for('login'))

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        new_subject = request.form.get('new_subject')
        if not all([name, username, password, role]):
            flash('All fields are required', 'error')
            return redirect(url_for('add_user'))
        if role.lower() not in ['teacher', 'student']:
            flash('Invalid role selected', 'error')
            return redirect(url_for('add_user'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            logger.warning(f"Add user failed: Username {username} already exists")
            return redirect(url_for('add_user'))
        user_id = generate_user_id(role.lower())
        user = User(
            user_id=user_id,
            name=name,
            username=username,
            password=generate_password_hash(password),
            role=role.lower()
        )
        db.session.add(user)
        new_subject_id = None
        if new_subject:
            existing_subject = Subject.query.filter_by(name=new_subject).first()
            if existing_subject:
                new_subject_id = existing_subject.id
            else:
                subject = Subject(name=new_subject)
                db.session.add(subject)
                db.session.flush()
                new_subject_id = subject.id
                logger.info(f"Added new subject: {new_subject}")
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding user: {str(e)}', 'error')
            logger.error(f"Error adding user {username}: {str(e)}")
            return redirect(url_for('add_user'))
        if role.lower() == 'teacher':
            subject_id = request.form.get('subject_id') or new_subject_id
            if subject_id:
                us = UserSubject(user_id=user.id, subject_id=subject_id, role_in_subject='teacher')
                db.session.add(us)
            else:
                flash('No subject selected for teacher. Subject is optional but recommended.', 'warning')
        elif role.lower() == 'student':
            subject_ids = request.form.getlist('subject_ids')
            if new_subject_id:
                subject_ids.append(str(new_subject_id))
            if subject_ids:
                for subject_id in subject_ids:
                    us = UserSubject(user_id=user.id, subject_id=subject_id, role_in_subject='student')
                    db.session.add(us)
            else:
                flash('No subjects selected for student. Subject is optional but recommended.', 'warning')
        try:
            db.session.commit()
            flash('User added successfully', 'success')
            return redirect(url_for('teachers' if role.lower() == 'teacher' else 'students'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error assigning subjects: {str(e)}', 'error')
            logger.error(f"Error assigning subjects for user {username}: {str(e)}")
            return redirect(url_for('add_user'))
    subjects = Subject.query.all()
    return render_template('add_user.html', subjects=subjects, csrf_token=session.get('csrf_token', ''))

@app.route('/teachers')
def teachers():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    teachers = UserSubject.query.filter_by(role_in_subject='teacher').all()
    return render_template('admin_teachers.html', teachers=teachers)

@app.route('/students')
def students():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    students_data = []
    user_subjects = UserSubject.query.filter_by(role_in_subject='student').all()
    for us in user_subjects:
        student = us.user_ref
        subject = us.subject_ref
        attendance = Attendance.query.filter_by(user_id=student.id, subject_id=subject.id).order_by(Attendance.entry_time.desc()).first()
        existing = next((item for item in students_data if item['student'].id == student.id), None)
        if existing:
            existing['subject_names'].append(subject.name)
            if attendance and (not existing['attendance'] or attendance.entry_time > existing['attendance'].entry_time):
                existing['attendance'] = attendance
        else:
            students_data.append({
                'student': student,
                'subject_names': [subject.name],
                'attendance': attendance
            })
    return render_template('admin_students.html', students=students_data)

@app.route('/teacher_dashboard_view/<int:teacher_id>')
def teacher_dashboard_view(teacher_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    try:
        user = User.query.get_or_404(teacher_id)
        if user.role != 'teacher':
            flash('User is not a teacher', 'error')
            return redirect(url_for('teachers'))
        user_subject = UserSubject.query.filter_by(user_id=user.id, role_in_subject='teacher').first()
        if not user_subject:
            logger.warning(f"No subject assigned to teacher {user.username} (ID: {user.id}) for admin view")
            flash('No subject assigned to this teacher', 'error')
            return render_template('teacher_dashboard.html', subject=None, schedules=None, attendance=None, students=None, user=user, is_admin_view=True)
        subject = user_subject.subject_ref
        if not subject:
            logger.warning(f"Subject not found for teacher {user.username} (ID: {user.id}) for admin view")
            flash('Assigned subject not found. Please contact the admin.', 'error')
            return render_template('teacher_dashboard.html', subject=None, schedules=None, attendance=None, students=None, user=user, is_admin_view=True)
        schedules = LectureSchedule.query.filter_by(subject_id=subject.id).all()
        students = User.query.join(UserSubject).filter(
            UserSubject.subject_id == subject.id,
            UserSubject.role_in_subject == 'student'
        ).all()
        attendance = Attendance.query.filter_by(subject_id=subject.id).all()
        logger.info(f"Teacher dashboard view loaded for {user.username} with subject: {subject.name}, {len(schedules)} schedules, {len(attendance)} attendance records, {len(students)} students")
        return render_template('teacher_dashboard.html', subject=subject, schedules=schedules, attendance=attendance, students=students, user=user, is_admin_view=True)
    except Exception as e:
        logger.error(f"Error loading teacher dashboard view for teacher ID {teacher_id}: {str(e)}")
        flash(f'Error loading teacher dashboard: {str(e)}', 'error')
        return redirect(url_for('teachers'))

@app.route('/student_dashboard_view/<int:student_id>')
def student_dashboard_view(student_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    try:
        user = User.query.get_or_404(student_id)
        if user.role != 'student':
            flash('User is not a student', 'error')
            return redirect(url_for('students'))
        user_subjects = UserSubject.query.filter_by(user_id=user.id, role_in_subject='student').all()
        subjects = [us.subject_ref for us in user_subjects if us.subject_ref]
        attendance = Attendance.query.filter_by(user_id=user.id).all()
        return render_template('student_dashboard.html', user=user, subjects=subjects, attendance=attendance, is_admin_view=True)
    except Exception as e:
        logger.error(f"Error loading student dashboard view for student ID {student_id}: {str(e)}")
        flash(f'Error loading student dashboard: {str(e)}', 'error')
        return redirect(url_for('students'))

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    user = User.query.get(user_id)
    if user:
        if user.role == 'admin':
            flash('Cannot delete admin user', 'error')
        else:
            try:
                UserSubject.query.filter_by(user_id=user_id).delete()
                Attendance.query.filter_by(user_id=user_id).delete()
                db.session.delete(user)
                db.session.commit()
                logger.info(f"Deleted user: {user.username}")
                flash('User deleted successfully', 'success')
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error deleting user {user.username}: {str(e)}")
                flash(f'Error deleting user: {str(e)}', 'error')
    return redirect(url_for('dashboard'))

@app.route('/add_subject', methods=['GET', 'POST'])
def add_subject():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form.get('name')
        if not name:
            flash('Subject name is required', 'error')
            return redirect(url_for('add_subject'))
        if Subject.query.filter_by(name=name).first():
            flash('Subject already exists', 'error')
            logger.warning(f"Add subject failed: Subject {name} already exists")
            return redirect(url_for('add_subject'))
        subject = Subject(name=name)
        db.session.add(subject)
        try:
            db.session.commit()
            logger.info(f"Added subject: {name}")
            flash('Subject added successfully', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding subject: {str(e)}', 'error')
            logger.error(f"Error adding subject {name}: {str(e)}")
            return redirect(url_for('add_subject'))
    return render_template('add_subject.html', csrf_token=session.get('csrf_token', ''))

@app.route('/delete_subject/<int:subject_id>')
def delete_subject(subject_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    subject = Subject.query.get(subject_id)
    if subject:
        try:
            UserSubject.query.filter_by(subject_id=subject_id).delete()
            Attendance.query.filter_by(subject_id=subject_id).delete()
            LectureSchedule.query.filter_by(subject_id=subject_id).delete()
            db.session.delete(subject)
            db.session.commit()
            logger.info(f"Deleted subject: {subject.name}")
            flash('Subject deleted successfully', 'success')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting subject {subject.name}: {str(e)}")
            flash(f'Error deleting subject: {str(e)}', 'error')
    return redirect(url_for('dashboard'))

@app.route('/add_or_edit_lecture_schedule', defaults={'schedule_id': None}, methods=['GET', 'POST'])
@app.route('/edit_lecture_schedule/<int:schedule_id>', methods=['GET', 'POST'])
def add_or_edit_lecture_schedule(schedule_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if user.role != 'admin':
        user_subject = UserSubject.query.filter_by(user_id=user.id, role_in_subject='teacher').first()
        if not user_subject:
            flash('No subject assigned to this teacher', 'error')
            return redirect(url_for('dashboard'))
        subject_id = user_subject.subject_id
    else:
        subject_id = None
    schedule = LectureSchedule.query.get(schedule_id) if schedule_id else None
    if schedule and schedule.subject_id != subject_id and user.role != 'admin':
        flash('You are not authorized to edit this schedule', 'error')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        if user.role == 'admin':
            subject_id = request.form.get('subject_id')
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')
        min_duration = request.form.get('min_duration')
        if not all([start_time, end_time, min_duration]):
            flash('All fields are required', 'error')
            return redirect(url_for('add_or_edit_lecture_schedule', schedule_id=schedule_id))
        try:
            start_time = datetime.strptime(start_time, '%Y-%m-%dT%H:%M')
            end_time = datetime.strptime(end_time, '%Y-%m-%dT%H:%M')
            min_duration = int(min_duration) * 60
        except ValueError:
            flash('Invalid date or time format', 'error')
            logger.warning(f"Add/edit schedule failed: Invalid date/time format")
            return redirect(url_for('add_or_edit_lecture_schedule', schedule_id=schedule_id))
        if start_time >= end_time:
            flash('End time must be after start time', 'error')
            logger.warning(f"Add/edit schedule failed: Invalid time range")
            return redirect(url_for('add_or_edit_lecture_schedule', schedule_id=schedule_id))
        if not schedule:
            schedule = LectureSchedule(subject_id=subject_id, start_time=start_time, end_time=end_time, min_attendance_duration=min_duration)
        else:
            schedule.subject_id = subject_id
            schedule.start_time = start_time
            schedule.end_time = end_time
            schedule.min_attendance_duration = min_duration
        db.session.add(schedule)
        try:
            db.session.commit()
            logger.info(f"{'Added' if not schedule_id else 'Edited'} lecture schedule for subject ID {subject_id}")
            flash('Lecture schedule saved successfully', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error saving schedule: {str(e)}', 'error')
            logger.error(f"Error saving schedule: {str(e)}")
            return redirect(url_for('add_or_edit_lecture_schedule', schedule_id=schedule_id))
    subjects = Subject.query.all() if user.role == 'admin' else [Subject.query.get(subject_id)]
    return render_template('edit_lecture_schedule.html', schedule=schedule, subjects=subjects, csrf_token=session.get('csrf_token', ''))

@app.route('/mark_attendance', defaults={'subject_id': None}, methods=['GET', 'POST'])
@app.route('/mark_attendance/<int:subject_id>', methods=['GET', 'POST'])
def mark_attendance(subject_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if user.role == 'admin' and subject_id:
        subject = Subject.query.get(subject_id)
        if not subject:
            flash('Subject not found', 'error')
            return redirect(url_for('dashboard'))
        students = User.query.join(UserSubject).filter(
            UserSubject.subject_id == subject_id,
            UserSubject.role_in_subject == 'student'
        ).all()
    else:
        user_subject = UserSubject.query.filter_by(user_id=user.id, role_in_subject='teacher').first()
        if not user_subject:
            flash('No subject assigned to this teacher', 'error')
            return redirect(url_for('dashboard'))
        subject = user_subject.subject_ref
        students = User.query.join(UserSubject).filter(
            UserSubject.subject_id == subject.id,
            UserSubject.role_in_subject == 'student'
        ).all()
    if request.method == 'POST':
        now = datetime.now()
        for student in students:
            status = request.form.get(f'status_{student.id}')
            if status:
                attendance = Attendance(
                    user_id=student.id,
                    subject_id=subject.id,
                    entry_time=now,
                    status=status,
                    duration=0
                )
                db.session.add(attendance)
        try:
            db.session.commit()
            logger.info(f"Marked attendance for subject: {subject.name}")
            flash('Attendance marked successfully', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error marking attendance: {str(e)}', 'error')
            logger.error(f"Error marking attendance for subject {subject.name}: {str(e)}")
            return redirect(url_for('mark_attendance', subject_id=subject_id))
    return render_template('mark_attendance.html', students=students, subject=subject, csrf_token=session.get('csrf_token', ''))

@app.route('/mark_attendance_student/<int:student_id>', methods=['GET', 'POST'])
def mark_attendance_student(student_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    student = User.query.get_or_404(student_id)
    user_subjects = UserSubject.query.filter_by(user_id=student.id, role_in_subject='student').all()
    subjects = [us.subject_ref for us in user_subjects]
    if request.method == 'POST':
        now = datetime.now()
        for subject in subjects:
            status = request.form.get(f'status_{subject.id}')
            if status:
                attendance = Attendance(
                    user_id=student.id,
                    subject_id=subject.id,
                    entry_time=now,
                    status=status,
                    duration=0
                )
                db.session.add(attendance)
        try:
            db.session.commit()
            logger.info(f"Marked attendance for student: {student.username}")
            flash('Attendance marked successfully', 'success')
            return redirect(url_for('students'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error marking attendance: {str(e)}', 'error')
            logger.error(f"Error marking attendance for student {student.username}: {str(e)}")
            return redirect(url_for('mark_attendance_student', student_id=student_id))
    return render_template('mark_attendance_student.html', student=student, subjects=subjects, csrf_token=session.get('csrf_token', ''))

@app.route('/record_exit/<int:attendance_id>', methods=['POST'])
def record_exit(attendance_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    attendance = Attendance.query.get_or_404(attendance_id)
    if user.role != 'admin':
        user_subject = UserSubject.query.filter_by(user_id=user.id, role_in_subject='teacher').first()
        if not user_subject or user_subject.subject_id != attendance.subject_id:
            flash('You are not authorized to record this exit', 'error')
            return redirect(url_for('dashboard'))
    if attendance.exit_time:
        flash('Exit time already recorded', 'error')
        return redirect(url_for('dashboard'))
    now = datetime.now()
    attendance.exit_time = now
    duration = int((now - attendance.entry_time).total_seconds())
    attendance.duration = duration
    lecture = LectureSchedule.query.filter(
        LectureSchedule.subject_id == attendance.subject_id,
        LectureSchedule.start_time <= attendance.entry_time,
        LectureSchedule.end_time >= attendance.entry_time
    ).first()
    if lecture:
        min_duration = lecture.min_attendance_duration
        attendance.status = 'present' if duration >= min_duration else 'absent'
    try:
        db.session.commit()
        logger.info(f"Recorded exit for attendance ID {attendance_id}")
        flash('Exit time recorded successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error recording exit: {str(e)}', 'error')
        logger.error(f"Error recording exit for attendance ID {attendance_id}: {str(e)}")
    return redirect(url_for('dashboard'))

@app.route('/change_teacher_subject/<int:teacher_id>', methods=['GET', 'POST'])
def change_teacher_subject(teacher_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    teacher = User.query.get_or_404(teacher_id)
    if teacher.role != 'teacher':
        flash('User is not a teacher.', 'error')
        logger.warning(f"Admin attempted to change subject for non-teacher {teacher.username}")
        return redirect(url_for('teachers'))
    current_subject = UserSubject.query.filter_by(user_id=teacher.id, role_in_subject='teacher').first()
    if request.method == 'POST':
        new_subject_id = request.form.get('subject_id')
        if not new_subject_id:
            flash('Please select a subject', 'error')
            return redirect(url_for('change_teacher_subject', teacher_id=teacher_id))
        new_subject = Subject.query.get(new_subject_id)
        if not new_subject:
            flash('Invalid subject selection', 'error')
            logger.warning(f"Change subject failed: Invalid subject for teacher {teacher.username}")
            return redirect(url_for('change_teacher_subject', teacher_id=teacher_id))
        UserSubject.query.filter_by(user_id=teacher.id, role_in_subject='teacher').delete()
        us = UserSubject(user_id=teacher.id, subject_id=new_subject_id, role_in_subject='teacher')
        db.session.add(us)
        try:
            db.session.commit()
            logger.info(f"Changed subject for teacher {teacher.username} to {new_subject.name}")
            flash('Teacher subject changed successfully', 'success')
            return redirect(url_for('teachers'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error changing subject: {str(e)}', 'error')
            logger.error(f"Error changing subject for teacher {teacher.username}: {str(e)}")
            return redirect(url_for('change_teacher_subject', teacher_id=teacher_id))
    subjects = Subject.query.all()
    return render_template('change_teacher_subject.html', teacher=teacher, subjects=subjects, current_subject=current_subject.subject_ref if current_subject else None, csrf_token=session.get('csrf_token', ''))

@app.route('/change_student_subject/<int:student_id>', methods=['GET', 'POST'])
def change_student_subject(student_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    student = User.query.get_or_404(student_id)
    if student.role != 'student':
        flash('User is not a student.', 'error')
        logger.warning(f"Admin attempted to change subject for non-student {student.username}")
        return redirect(url_for('students'))
    current_subjects = UserSubject.query.filter_by(user_id=student.id, role_in_subject='student').all()
    if request.method == 'POST':
        UserSubject.query.filter_by(user_id=student.id, role_in_subject='student').delete()
        subject_ids = request.form.getlist('subject_ids')
        if not subject_ids:
            flash('At least one subject must be selected', 'error')
            return redirect(url_for('change_student_subject', student_id=student_id))
        subjects = Subject.query.filter(Subject.id.in_(subject_ids)).all()
        if not subjects:
            flash('Invalid subject selection', 'error')
            return redirect(url_for('change_student_subject', student_id=student_id))
        for subject in subjects:
            us = UserSubject(user_id=student.id, subject_id=subject.id, role_in_subject='student')
            db.session.add(us)
        try:
            db.session.commit()
            logger.info(f"Changed subjects for student {student.username} to {[s.name for s in subjects]}")
            flash('Student subjects changed successfully', 'success')
            return redirect(url_for('students'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error changing subjects: {str(e)}', 'error')
            logger.error(f"Error changing subjects for student {student.username}: {str(e)}")
    subjects = Subject.query.all()
    return render_template('change_student_subject.html', student=student, subjects=subjects, current_subjects=current_subjects, csrf_token=session.get('csrf_token', ''))

@app.route('/sync_face_logs', methods=['POST'])
def sync_face_logs():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    try:
        sync_face_logs_to_db()
        archive_face_logs()
        return jsonify({'status': 'success', 'message': 'Face logs synced successfully'})
    except Exception as e:
        logger.error(f"Error syncing face logs: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def init_db():
    """Initialize the database with an admin user if none exist."""
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(role='admin').first():
            admin = User(
                user_id='ADMIN001',
                name='Admin User',
                username='admin',
                password=generate_password_hash('admin123'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            logger.info("Initialized database with admin user")

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)