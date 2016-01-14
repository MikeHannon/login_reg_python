from flask import Flask, render_template, request, redirect, session, flash
import re
from connection import MySQLConnector
from flask.ext.bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = 'my_secret_key'
MYSQL = MySQLConnector('users')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+.[a-zA-Z]*$')


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods = ['POST'])
def login():
    errors = {};
    print "*************LOGIN**************"
    print request.form
    print "***************************"
    query = "SELECT * from users where email = '{}'".format(request.form['email']);
    print (query)
    existing_user = MYSQL.fetch(query)
    print (existing_user)
    if len(existing_user) == 0:
        flash({"register": "Please register"})
        return redirect('/')
    else:
        if len(request.form['password']) == 0:
            flash({"check_password": "Please enter your password"})
            return redirect('/')

        password = request.form['password']
        # returns a true false!
        if bcrypt.check_password_hash(existing_user[0]['password'], password):
            session['user']={'first_name':existing_user[0]['first_name'], 'last_name':existing_user[0]['last_name'], 'id':existing_user[0]['id']}
            return redirect('/success')
        #to generate
    flash ({'pw_user_mismatch':'user or password unavailable'})
    return redirect('/')

@app.route('/register', methods = ['POST'])
def register():
    errors = {};
    print "*************REGISTER**************"
    print request.form
    print "***************************"
    # is email in DB already???
    query = "SELECT email from users where email = '{}'".format(request.form['email']);
    print (query)
    existing_user = MYSQL.fetch(query)
    if len(existing_user) == 0:

            #Have an error
        if len(request.form['first_name']) == 0:
            errors['first_name_exist'] = "Please enter a first_name"
        elif not request.form['first_name'].isalpha():
            errors['first_name_alpha'] = "Please us letters only"
            #Have an error
        if len(request.form['last_name']) == 0:
            errors['last_name_exist'] = "Please enter a last_name"
            #Have an error
        if len(request.form['password']) < 7:
            errors['password_length'] = "Password must be longer than 7 letters"
            #Have an error
        if not EMAIL_REGEX.match(request.form['email'
        ]):
            errors['email'] = "Not a valid email"
            #Have an error
        if request.form['password'] != request.form['confirm_password']:
            errors['password_match'] = "Please re-enter password and confirm password, these must match"
        if errors:
            flash(errors)
            return redirect('/')
        password = request.form['password']
        hashed_pw = bcrypt.generate_password_hash(password)
        query = "INSERT into users (first_name, last_name, password, email, created_at, updated_at, last_logged_in_at) values ('{}','{}','{}','{}',NOW(), NOW(), NOW())".format(request.form['first_name'], request.form['last_name'],hashed_pw,request.form['email'])
        MYSQL.run_mysql_query(query)
        flash({'success':'You have successfully registered in, please login'})
        return redirect('/')

    else:
        errors['user_exists'] = "User already exists please login or register with a different email"#Have an error
        return redirect('/')

    return "REGISTER"

@app.route('/success')
def success():
    try:
        session['user']
        return render_template('show.html')
    except:
        return redirect('/')

@app.route('/reset')
def reset():
    session.pop('user')
    return redirect('/')

if __name__ == '__main__':
  app.run(debug = True)
