import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.utils import secure_filename
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # Limit upload size to 2MB


# Helper function to check if the uploaded file is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Helper function to connect to the database
def get_db_connection():
    conn = sqlite3.connect('smart_neighborhood.db')
    conn.row_factory = sqlite3.Row  # To access columns by name
    return conn

@app.route('/')
def index():
    conn = get_db_connection()
    resources = conn.execute('''
        SELECT Resource.*, User.name AS owner_name
        FROM Resource
        JOIN User ON Resource.user_id = User.user_id
        ORDER BY date_posted DESC
    ''').fetchall()

    top_users = conn.execute('SELECT user_id, name, reputation_score FROM User ORDER BY reputation_score DESC LIMIT 5').fetchall()
    reviews = conn.execute('''
        SELECT Review.*, User.name AS reviewer_name, Resource.title AS resource_title, Resource.images AS resource_image
        FROM Review
        JOIN User ON Review.reviewer_id = User.user_id
        JOIN Resource ON Review.resource_id = Resource.resource_id
        ORDER BY Review.timestamp DESC LIMIT 5
    ''').fetchall()
    conn.close()

    return render_template('index.html', resources=resources, top_users=top_users, reviews=reviews)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO User (name, email, password, reputation_score) VALUES (?, ?, ?, 0)', (name, email, password))
            conn.commit()
            flash('Registration successful! Please log in.')
        except sqlite3.IntegrityError:
            flash('Email already registered.')
        finally:
            conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM User WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['user_id']
            session['name'] = user['name']
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('name', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access your dashboard.')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    listings = conn.execute('SELECT * FROM Resource WHERE user_id = ? ORDER BY date_posted DESC', (user_id,)).fetchall()
    messages = conn.execute('SELECT * FROM Message WHERE sender_id = ? OR receiver_id = ?', (user_id, user_id)).fetchall()
    reviews = conn.execute('SELECT * FROM Review WHERE user_id = ?', (user_id,)).fetchall()
    reservations = conn.execute('''
        SELECT Reservation.*, Resource.title AS resource_title, Resource.images AS resource_image
        FROM Reservation
        JOIN Resource ON Reservation.resource_id = Resource.resource_id
        WHERE Reservation.user_id = ?
        ORDER BY Reservation.start_date ASC
    ''', (user_id,)).fetchall()
    pending_reservations = conn.execute('''
        SELECT Reservation.*, Resource.title AS resource_title, User.name AS user_name
        FROM Reservation
        JOIN Resource ON Reservation.resource_id = Resource.resource_id
        JOIN User ON Reservation.user_id = User.user_id
        WHERE Resource.user_id = ? AND Reservation.status = 'pending'
        ORDER BY Reservation.start_date ASC
    ''', (user_id,)).fetchall()
    conn.close()

    return render_template('dashboard.html', listings=listings, messages=messages, reviews=reviews, reservations=reservations, pending_reservations=pending_reservations)

@app.route('/add_resource', methods=['GET', 'POST'])
def add_resource():
    if 'user_id' not in session:
        flash('Please log in to add a resource.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_id = session['user_id']
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        date_posted = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        image_filename = None  # Default if no image is uploaded

        # Handle image upload
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(image_path)
                image_filename = 'uploads/' + filename  # Store the relative path for database storage

        # Insert data into the database
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO Resource (user_id, title, description, images, category, availability, date_posted) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (user_id, title, description, image_filename, category, 'available', date_posted)
        )
        conn.commit()
        conn.close()

        flash('Resource added successfully!')
        return redirect(url_for('dashboard'))

    return render_template('add_resource.html')

@app.route('/resource/<int:resource_id>')
def resource_details(resource_id):
    conn = get_db_connection()
    resource = conn.execute('SELECT * FROM Resource WHERE resource_id = ?', (resource_id,)).fetchone()
    reviews = conn.execute(
        'SELECT Review.rating, Review.comment, Review.timestamp, User.name '
        'FROM Review JOIN User ON Review.reviewer_id = User.user_id '
        'WHERE Review.resource_id = ? ORDER BY Review.timestamp DESC', 
        (resource_id,)
    ).fetchall()
    average_rating = conn.execute(
        'SELECT AVG(rating) as avg_rating FROM Review WHERE resource_id = ?', 
        (resource_id,)
    ).fetchone()['avg_rating']
    conn.close()

    if resource is None:
        flash('Resource not found.')
        return redirect(url_for('index'))

    average_rating = round(average_rating, 2) if average_rating else 'No ratings yet'
    return render_template('resource_details.html', resource=resource, reviews=reviews, average_rating=average_rating)

@app.route('/profile/<int:user_id>', methods=['GET', 'POST'])
def profile(user_id):
    if 'user_id' not in session or session['user_id'] != user_id:
        flash('You do not have permission to edit this profile.')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM User WHERE user_id = ?', (user_id,)).fetchone()

    if user is None:
        conn.close()
        flash('User not found.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        location = request.form['location']
        profile_image = user['profile_image']  # Keep current image by default

        # Check if a new image is uploaded
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(image_path)
                profile_image = 'uploads/' + filename  # Update image path in database

        # Update user profile in the database
        conn.execute(
            'UPDATE User SET name = ?, location = ?, profile_image = ? WHERE user_id = ?',
            (name, location, profile_image, user_id)
        )
        conn.commit()
        conn.close()

        flash('Profile updated successfully!')
        return redirect(url_for('edit_profile', user_id=user_id))

    conn.close()
    return render_template('edit_profile.html', user=user)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('Please log in to edit your profile.')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM User WHERE user_id = ?', (user_id,)).fetchone()

    if request.method == 'POST':
        name = request.form['name']
        location = request.form['location']
        profile_image = user['profile_image']  # Default to the existing image

        # Handle profile image upload
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(image_path)
                profile_image = 'uploads/' + filename  # Save the relative path

        # Update user profile in the database
        conn.execute(
            'UPDATE User SET name = ?, location = ?, profile_image = ? WHERE user_id = ?',
            (name, location, profile_image, user_id)
        )
        conn.commit()
        conn.close()

        flash('Profile updated successfully!')
        return redirect(url_for('profile', user_id=user_id))

    conn.close()
    return render_template('profile.html', user=user)

@app.route('/forum')
def forum():
    conn = get_db_connection()
    messages = conn.execute(
        'SELECT Message.content, Message.timestamp, sender.name AS sender_name, receiver.name AS receiver_name '
        'FROM Message '
        'JOIN User AS sender ON Message.sender_id = sender.user_id '
        'JOIN User AS receiver ON Message.receiver_id = receiver.user_id '
        'ORDER BY Message.timestamp DESC'
    ).fetchall()
    conn.close()

    return render_template('forum.html', messages=messages)

@app.route('/send_message', methods=['GET', 'POST'])
def send_message():
    if 'user_id' not in session:
        flash('Please log in to send messages.')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()

    if request.method == 'POST':
        sender_id = session['user_id']
        receiver_id = request.form['receiver_id']
        content = request.form['content']
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        conn.execute(
            'INSERT INTO Message (sender_id, receiver_id, content, timestamp) VALUES (?, ?, ?, ?)',
            (sender_id, receiver_id, content, timestamp)
        )
        conn.commit()
        conn.close()
        flash('Message sent successfully!')
        return redirect(url_for('forum'))

    # Fetch all users except the logged-in user for the recipient list
    users = conn.execute('SELECT user_id, name FROM User WHERE user_id != ?', (user_id,)).fetchall()
    conn.close()

    return render_template('send_message.html', users=users)

@app.route('/add_review/<int:resource_id>', methods=['GET', 'POST'])
def add_review(resource_id):
    if 'user_id' not in session:
        flash('Please log in to leave a review.')
        return redirect(url_for('login'))

    conn = get_db_connection()
    resource = conn.execute('SELECT * FROM Resource WHERE resource_id = ?', (resource_id,)).fetchone()

    # Prevent users from reviewing their own listings
    if resource and resource['user_id'] == session['user_id']:
        conn.close()
        flash('You cannot review your own listing.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        rating = request.form['rating']
        comment = request.form['comment']
        reviewer_id = session['user_id']
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Insert review into the database
        conn.execute(
            'INSERT INTO Review (resource_id, reviewer_id, rating, comment, timestamp) VALUES (?, ?, ?, ?, ?)',
            (resource_id, reviewer_id, rating, comment, timestamp)
        )
        conn.commit()
        conn.close()

        flash('Review added successfully!')
        return redirect(url_for('index'))

    conn.close()
    return render_template('add_review.html', resource=resource)

@app.route('/rate_user/<int:user_id>', methods=['GET', 'POST'])
def rate_user(user_id):
    if 'user_id' not in session:
        flash('Please log in to rate users.')
        return redirect(url_for('login'))

    if user_id == session['user_id']:
        flash('You cannot rate yourself.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        rating = int(request.form['rating'])
        reviewer_id = session['user_id']
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        conn = get_db_connection()
        # Insert the new rating into the UserRating table
        conn.execute(
            'INSERT INTO UserRating (user_id, reviewer_id, rating, timestamp) VALUES (?, ?, ?, ?)',
            (user_id, reviewer_id, rating, timestamp)
        )
        conn.commit()

        # Calculate the new average rating for the user
        ratings = conn.execute(
            'SELECT AVG(rating) as average_rating FROM UserRating WHERE user_id = ?',
            (user_id,)
        ).fetchone()

        if ratings and ratings['average_rating'] is not None:
            new_reputation_score = round(ratings['average_rating'], 2)
            
            # Update the user's reputation score in the User table
            conn.execute(
                'UPDATE User SET reputation_score = ? WHERE user_id = ?',
                (new_reputation_score, user_id)
            )
            conn.commit()

        conn.close()
        flash('User rating submitted successfully, and reputation score updated!')
        return redirect(url_for('index'))

    return render_template('rate_user.html', user_id=user_id)

@app.route('/delete_resource/<int:resource_id>', methods=['POST'])
def delete_resource(resource_id):
    if 'user_id' not in session:
        flash('Please log in to delete a resource.')
        return redirect(url_for('login'))

    user_id = session['user_id']

    conn = get_db_connection()
    # Check if the resource belongs to the logged-in user
    resource = conn.execute('SELECT * FROM Resource WHERE resource_id = ? AND user_id = ?', (resource_id, user_id)).fetchone()

    if resource:
        # Delete the resource from the database
        conn.execute('DELETE FROM Resource WHERE resource_id = ?', (resource_id,))
        conn.commit()
        flash('Resource deleted successfully!')
    else:
        flash('You do not have permission to delete this resource.')

    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/reserve/<int:resource_id>', methods=['GET', 'POST'])
def reserve_resource(resource_id):
    if 'user_id' not in session:
        flash('Please log in to reserve a resource.')
        return redirect(url_for('login'))

    conn = get_db_connection()
    resource = conn.execute('SELECT * FROM Resource WHERE resource_id = ?', (resource_id,)).fetchone()

    if not resource:
        flash('Resource not found.')
        conn.close()
        return redirect(url_for('index'))

    if request.method == 'POST':
        user_id = session['user_id']
        start_date = request.form['start_date']
        end_date = request.form['end_date']

        # Check for conflicts with existing reservations
        conflicts = conn.execute('''
            SELECT * FROM Reservation 
            WHERE resource_id = ? AND (
                (start_date <= ? AND end_date >= ?) OR 
                (start_date <= ? AND end_date >= ?)
            )
        ''', (resource_id, start_date, start_date, end_date, end_date)).fetchall()

        if conflicts:
            flash('This resource is already reserved for the selected dates. Please choose different dates.')
        else:
            # Insert new reservation into the database
            conn.execute('''
                INSERT INTO Reservation (resource_id, user_id, start_date, end_date, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (resource_id, user_id, start_date, end_date, 'pending'))
            conn.commit()
            flash('Reservation created successfully! You will be notified if your reservation is approved.')

        conn.close()
        return redirect(url_for('index'))

    conn.close()
    return render_template('reserve.html', resource=resource)

@app.route('/accept_reservation/<int:reservation_id>', methods=['POST'])
def accept_reservation(reservation_id):
    if 'user_id' not in session:
        flash('Please log in to manage reservations.')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()

    # Check if the logged-in user owns the resource for the reservation
    reservation = conn.execute('''
        SELECT Reservation.*, Resource.user_id AS owner_id
        FROM Reservation
        JOIN Resource ON Reservation.resource_id = Resource.resource_id
        WHERE Reservation.reservation_id = ? AND Resource.user_id = ?
    ''', (reservation_id, user_id)).fetchone()

    if reservation:
        # Update reservation status to 'accepted'
        conn.execute('UPDATE Reservation SET status = ? WHERE reservation_id = ?', ('accepted', reservation_id))
        conn.commit()
        flash('Reservation accepted successfully!')
    else:
        flash('You do not have permission to manage this reservation.')

    conn.close()
    return redirect(url_for('dashboard'))


@app.route('/decline_reservation/<int:reservation_id>', methods=['POST'])
def decline_reservation(reservation_id):
    if 'user_id' not in session:
        flash('Please log in to manage reservations.')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()

    # Check if the logged-in user owns the resource for the reservation
    reservation = conn.execute('''
        SELECT Reservation.*, Resource.user_id AS owner_id
        FROM Reservation
        JOIN Resource ON Reservation.resource_id = Resource.resource_id
        WHERE Reservation.reservation_id = ? AND Resource.user_id = ?
    ''', (reservation_id, user_id)).fetchone()

    if reservation:
        # Update reservation status to 'declined'
        conn.execute('UPDATE Reservation SET status = ? WHERE reservation_id = ?', ('declined', reservation_id))
        conn.commit()
        flash('Reservation declined successfully!')
    else:
        flash('You do not have permission to manage this reservation.')

    conn.close()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)


