
import pymysql
from functions import *
import datetime
connection = pymysql.connect(host='localhost', user='root',
                             password='', database='FleetDB')

from flask import *
app = Flask(__name__)
app.secret_key = "QGTggg#$$#455_TThh@@ggg_jjj%%&^576" # session ids will be encrypted using this key

# Functions to check sessions





def check_user():
    if 'user_id' in session:
        return True
    else:
        return False

def check_role():
    if 'role' in session:
        role = session['role']
        return role
    else:
        session.clear()
        return redirect('/login')

def get_userid():
    if 'user_id' in session:
        user_id = session['user_id']
        return user_id
    else:
        session.clear()
        return redirect('/login')


@app.route("/logout")
def logout():
    #session.pop('user_id', None)
    session.clear()
    return redirect('/login')


@app.route('/login', methods = ['POST','GET'])
def login():
    if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            sql = "select * from users where email = %s"
            cursor = connection.cursor()
            cursor.execute(sql, email)
            if cursor.rowcount == 0:
                return render_template('login.html', message = "Wrong Email")
            else:
                row = cursor.fetchone()
                if row[5] == 'inactive':
                    return render_template('login.html',message ='Account Inactive, Please Wait For Approval')
                elif row[5] =='active':
                    hashed_password = row[6] # This is hashed pass from db
                    print("Hashed Pass", hashed_password)
                    # Verify that the hashed password is same as hashed pass from DB
                    status = password_verify(password, hashed_password)
                    print("Login Status", status)
                    if status:
                        # One Way Authentication Ends Here, Redirect user to Main Dash
                        # Two Way Can be done By Sending OTP to user Phone.
                        phone = row[8] # This phone is encrypted
                        # Decrypt it
                        decrypted_phone = decrypt(phone)
                        print("DEC PHONE", decrypted_phone)

                        otp = generate_random()
                        send_sms(decrypted_phone, "Your OTP is {}, Do not share with Anyone"
                                 .format(otp))

                        time = datetime.datetime.now()
                        sqlotp = "update users set otp = %s, otptime = %s where email = %s"
                        cursor = connection.cursor()
                        cursor.execute(sqlotp, (password_hash(otp), time, email))
                        connection.commit()
                        cursor.close()
                        # ACTIVATE SESSIONS
                        session['fname'] = row[1]  # fname
                        session['email'] = row[9]   #email
                        return redirect('/confirm_otp') # Move to another route
                    else:
                        return render_template('login.html', message = "Wrong Password")


    else:
        return render_template('login.html')

@app.route('/confirm_otp', methods = ['POST','GET'])
def confirm_otp():
    if 'email' in session:
        if request.method == 'POST':
            email = session['email']
            otp = request.form['otp']

            sql = "select * from users where email = %s"
            cursor = connection.cursor()
            cursor.execute(sql, (email))
            row = cursor.fetchone()
            otp_hash = row[11] #hashed OTP
            otp_time = row[12] # Otp time
            # convert otp time from str to datetime
            prev_time = datetime.datetime.strptime(otp_time, '%Y-%m-%d %H:%M:%S.%f')
            # get time now
            time_now = datetime.datetime.now()
            # find difference
            diff = time_now - prev_time
            if diff.total_seconds() > 60:
                return render_template('confirm_otp.html', message="OTP Expired")
            else:
                status = password_verify(otp, otp_hash)
                if status:
                    session['fname'] = row[1]  # fname
                    session['role'] = row[7]  # role
                    session['user_id'] = row[0]  # user_id
                    return redirect('/') # Two way Auth OK
                else:
                    return render_template('confirm_otp.html', message="Wrong OTP")

        else:
             return render_template('confirm_otp.html')

    else:
         return redirect('/login')
@app.route('/')
def dashboard():
    if check_user():
        return render_template('dashboard.html')
    else:
        return redirect('/login')


@app.route('/addMake', methods = ['POST', 'GET'])
def addmake():
    if check_user() and check_role() == "admin":
        if request.method == 'POST':
            make = request.form['make']
            if not make:
                return jsonify({'error1':'Please Enter make'})
            else:
                cursor = connection.cursor()
                sql = "insert into vehicle_make(make_name) values(%s)"
                try:
                    cursor.execute(sql, (make))
                    connection.commit()
                    return jsonify({'success': 'Make Added'})
                except:
                    connection.rollback()
                    return jsonify({'error2': 'Make Not Added'})

        else:
            return render_template('admin/addmake.html')
    else:
        return redirect('/login')

@app.route('/addLocation', methods = ['POST', 'GET'])
def addLocation():
    if check_user() and check_role() == "admin":
        if request.method == 'POST':
            location = request.form['location']
            if not location:
                return jsonify({'error1':'Please Enter location'})
            else:
                cursor = connection.cursor()
                sql = "insert into locations(loc_name) values(%s)"
                try:
                    cursor.execute(sql, (location))
                    connection.commit()
                    return jsonify({'success': 'Location Added'})
                except:
                    connection.rollback()
                    return jsonify({'error2': 'Location Not Added'})

        else:
            return render_template('admin/addlocations.html')
    else:
        return redirect('/login')

@app.route('/addModel', methods = ['POST', 'GET'])
def addModel():
    if check_user() and check_role() == "admin":
        if request.method == 'POST':
            model = request.form['model']
            make_id = request.form['make_id']
            if not model or not make_id:
                return jsonify({'error1':'Please Empty Fields'})
            else:
                cursor = connection.cursor()
                sql = "insert into vehicle_model(make_id,model_name) values(%s, %s)"
                try:
                    cursor.execute(sql, (make_id, model))
                    connection.commit()
                    return jsonify({'success': 'Model Added'})
                except:
                    connection.rollback()
                    return jsonify({'error2': 'Model Not Added'})
        else:
            # get makes from the database
            sql = "select * from vehicle_make order by make_name asc"
            cursor = connection.cursor()
            cursor.execute(sql)
            makes = cursor.fetchall()
            return render_template('admin/addmodel.html', makes = makes)
    else:
        return redirect('/login')


@app.route('/addType', methods = ['POST', 'GET'])
def addType():
    if check_user() and check_role() == "admin":
        if request.method == 'POST':
            type = request.form['type']
            if not type:
                return jsonify({'error1':'Please Enter Type'})
            else:
                cursor = connection.cursor()
                sql = "insert into vehicle_types(type_name) values(%s)"
                try:
                    cursor.execute(sql, (type))
                    connection.commit()
                    return jsonify({'success': 'Type Added'})
                except:
                    connection.rollback()
                    return jsonify({'error2': 'Type Not Added'})

        else:
            return render_template('admin/addtype.html')
    else:
        return redirect('/login')



app.run(debug=True)