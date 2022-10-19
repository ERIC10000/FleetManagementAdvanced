import pymysql
from functions import *
import datetime
from werkzeug.utils import secure_filename
import os

connection = pymysql.connect(host='localhost', user='root',
                             password='', database='FleetDB')

from flask import *

app = Flask(__name__)
app.secret_key = "QGTggg#$$#455_TThh@@ggg_jjj%%&^576"  # session ids will be encrypted using this key
UPLOAD_FOLDER = "static/images"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024  # ACCEPT ONLY  < 4mbs
# Functions to check sessions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}


def allowed_files(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


# print(allowed_files("kdfldfkl.pdf"))
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
    # session.pop('user_id', None)
    session.clear()
    return redirect('/login')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        sql = "select * from users where email = %s"
        cursor = connection.cursor()
        cursor.execute(sql, email)
        if cursor.rowcount == 0:
            return render_template('login.html', message="Wrong Email")
        else:
            row = cursor.fetchone()
            if row[5] == 'inactive':
                return render_template('login.html', message='Account Inactive, Please Wait For Approval')
            elif row[5] == 'active':
                hashed_password = row[6]  # This is hashed pass from db
                print("Hashed Pass", hashed_password)
                # Verify that the hashed password is same as hashed pass from DB
                status = password_verify(password, hashed_password)
                print("Login Status", status)
                if status:
                    # One Way Authentication Ends Here, Redirect user to Main Dash
                    # Two Way Can be done By Sending OTP to user Phone.
                    phone = row[8]  # This phone is encrypted
                    # Decrypt it
                    decrypted_phone = decrypt(phone)
                    print("DEC PHONE", decrypted_phone)

                    otp = generate_random()
                    # send_sms(decrypted_phone, "Your OTP is {}, Do not share with Anyone"
                    #          .format(otp))

                    time = datetime.datetime.now()
                    sqlotp = "update users set otp = %s, otptime = %s where email = %s"
                    cursor = connection.cursor()
                    cursor.execute(sqlotp, (password_hash(otp), time, email))
                    connection.commit()
                    cursor.close()
                    # ACTIVATE SESSIONS
                    session['fname'] = row[1]  # fname
                    session['email'] = row[9]  # email
                    return redirect('/confirm_otp')  # Move to another route
                else:
                    return render_template('login.html', message="Wrong Password")


    else:
        return render_template('login.html')


@app.route('/confirm_otp', methods=['POST', 'GET'])
def confirm_otp():
    if 'email' in session:
        if request.method == 'POST':
            email = session['email']
            otp = request.form['otp']

            sql = "select * from users where email = %s"
            cursor = connection.cursor()
            cursor.execute(sql, (email))
            row = cursor.fetchone()
            otp_hash = row[11]  # hashed OTP
            otp_time = row[12]  # Otp time
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
                    session['img'] = row[13]  # user_id
                    return redirect('/')  # Two way Auth OK
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


@app.route('/addMake', methods=['POST', 'GET'])
def addmake():
    if check_user() and check_role() == "admin":
        if request.method == 'POST':
            make = request.form['make']
            if not make:
                return jsonify({'error1': 'Please Enter make'})
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


@app.route('/addLocation', methods=['POST', 'GET'])
def addLocation():
    if check_user() and check_role() == "admin":
        if request.method == 'POST':
            location = request.form['location']
            if not location:
                return jsonify({'error1': 'Please Enter location'})
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


@app.route('/addModel', methods=['POST', 'GET'])
def addModel():
    if check_user() and check_role() == "admin":
        if request.method == 'POST':
            model = request.form['model']
            make_id = request.form['make_id']
            if not model or not make_id:
                return jsonify({'error1': 'Please Empty Fields'})
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
            return render_template('admin/addmodel.html', makes=makes)
    else:
        return redirect('/login')


@app.route('/addType', methods=['POST', 'GET'])
def addType():
    if check_user() and check_role() == "admin":
        if request.method == 'POST':
            type = request.form['type']
            if not type:
                return jsonify({'error1': 'Please Enter Type'})
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


@app.route('/addUser', methods=['POST', 'GET'])
def addUser():
    if check_user() and check_role() == "admin":
        if request.method == 'POST':
            fname = request.form['fname']
            lname = request.form['lname']
            surname = request.form['surname']
            gender = request.form['gender']
            password = generate_random()
            role = request.form['role']
            phone = request.form['phone']
            email = request.form['email']
            regex = "^\+254\d{9}"
            import re
            if not fname:
                return jsonify({'errorFname': 'Please Enter First Name'})

            elif not lname:
                return jsonify({'errorLname': 'Please Enter Last Name'})

            elif not surname:
                return jsonify({'errorSurname': 'Please Enter Surname'})

            elif not gender:
                return jsonify({'errorGender': 'Please Enter Gender'})

            elif role not in ['admin', 'finance', 'operations', 'guest', 'service']:
                return jsonify({'errorRole': 'Invalid Role'})

            elif not re.match(regex, phone):
                return jsonify({'errorPhone': 'Please Enter Valid Phone i.e +254XXXXXXXXX'})

            elif not validate_email(email):
                return jsonify({'errorEmail': 'Please Enter Valid Email'})

            else:
                sqlCheck = "select * from users where email = %s"
                cursor = connection.cursor()
                cursor.execute(sqlCheck, (email))
                if cursor.rowcount > 0:
                    return jsonify({'errorEmail': 'Email Already Taken'})
                else:
                    cursor = connection.cursor()
                    sql = '''insert into users(fname, lname, surname, gender, password, role, phone, email) 
                    values(%s,%s,%s,%s,%s,%s,%s,%s)'''
                    try:
                        cursor.execute(sql, (fname, lname, surname, gender, password_hash(password),
                                             role, encrypt(phone), email))

                        connection.commit()
                        message = '''Hello {}, You are signed in as {}, Login using Your Email 
                        and Password {}'''.format(fname, role, password)
                        send_sms(phone, message)
                        return jsonify({'success': 'User Added'})
                    except:
                        connection.rollback()
                        return jsonify({'error2': 'User Not Added'})

        else:
            return render_template('admin/adduser.html')
    else:
        return redirect('/login')


@app.route('/profile')
def profile():
    if check_user():
        user_id = get_userid()
        sql = "select * from users where user_id = %s"
        cursor = connection.cursor()
        cursor.execute(sql, (user_id))
        row = cursor.fetchone()
        return render_template("profile.html", row=row)
    else:
        return redirect('/login')


@app.template_filter()  # this function is called in a template
def data_decrypt(encrypted_data):
    decrypted = decrypt(encrypted_data)
    return decrypted


@app.route('/change_password', methods=['POST', 'GET'])
def change_password():
    if check_user():
        if request.method == 'POST':
            user_id = get_userid()
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']

            sql = "select * from users where user_id = %s"
            cursor = connection.cursor()
            cursor.execute(sql, (user_id))
            # get row containing the current password from DB
            row = cursor.fetchone()
            hashed_password = row[6]
            status = password_verify(current_password, hashed_password)
            if status:
                print("Current is okay")
                response = passwordValidity(new_password)
                print("tttttttttt", response)
                if response == True:
                    print("New is okay")
                    if new_password != confirm_password:
                        return jsonify({'confirmWrong': "Password Do Not match!"})
                    else:
                        print("Confirm is okay")
                        sql = "update users set password = %s where user_id = %s"
                        cursor = connection.cursor()
                        try:
                            cursor.execute(sql, (password_hash(new_password), user_id))
                            connection.commit()
                            return jsonify({'success': "Password Changed!"})
                        except:
                            connection.rollback()
                            return jsonify({'error': "Password Was Not Changed!"})
                else:
                    return jsonify({'newWrong': response})

            else:
                return jsonify({'currentWrong': 'Current Password is Wrong!'})

        else:
            return render_template('change_password.html')
    else:
        return redirect('/login')


@app.route('/addOwner', methods=['POST', 'GET'])
def addOwner():
    if check_user() and check_role() == "admin":
        if request.method == 'POST':
            fname = request.form['fname']
            lname = request.form['lname']
            surname = request.form['surname']
            email = request.form['email']
            address = request.form['address']
            loc_id = request.form['loc_id']
            # passport_pic = request.form['passport_pic']
            id_no = request.form['id_no']
            dob = request.form['dob']
            phone = request.form['phone']
            user_id = get_userid()  # Logged in person
            password = generate_random()  # Generate Random Password
            files = request.files.getlist("files[]")
            for file in files:
                if file and allowed_files(file.filename):
                    filename = secure_filename(file.filename)
                    uniquefilename = "{}{}".format(generate_random(), filename)  # add random strings to filename
                    # Upload the file using the random file name.
                    try:
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], uniquefilename))
                        session['uniquefilename'] = uniquefilename
                    except Exception as error:
                        session['uniquefilename'] = ""
                        print("Upload error", error)

                else:
                    return jsonify({"error": "Invalid File, Upload Only png, jpeg, "})

            if not fname:
                return jsonify({'error': 'First name is Empty!'})
            elif not lname:
                return jsonify({'error': 'Last name is Empty!'})
            elif not validate_email(email):
                return jsonify({'error': 'Email is Invalid'})
            elif not id_no:
                return jsonify({'error': 'Id no is Empty!'})
            elif not dob:
                return jsonify({'error': 'Your DOB is invalid'})
            elif not check_phone(phone):
                return jsonify({'error': 'Invalid Phone use +254XXXXXXXXX'})
            else:
                cursor = connection.cursor()
                sql = '''insert into owners(fname,lname, surname, phone, email, address,
                loc_id,passport_pic, id_no, dob, user_id, password) 
                values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''
                try:
                    cursor.execute(sql, (fname, lname, surname, encrypt(phone), email,
                                         address, loc_id, session['uniquefilename'], id_no, dob,
                                         user_id, password_hash(password)))
                    connection.commit()
                    message = '''Thank you for Joining FleetS, Download app from link 
                    Login with your email and password: {} To track your Vehicles'''.format(password)
                    send_sms(phone, message)
                    return jsonify({'success': 'Owner Added'})
                except:
                    connection.rollback()
                    return jsonify({'error2': 'Owner Not Added'})
        else:
            # get Locations from the database
            locations = getlocations()
            return render_template('admin/addowners.html', locations=locations)
    else:
        return redirect('/login')


@app.route('/addDriver', methods=['POST', 'GET'])
def addDriver():
    if check_user() and check_role() == "admin":
        if request.method == 'POST':
            fname = request.form['fname']
            lname = request.form['lname']
            surname = request.form['surname']
            email = request.form['email']
            dl_no = request.form['dl_no']
            loc_id = request.form['loc_id']
            dl_no_expiry = request.form['dl_no_expiry']
            # passport_pic = request.form['passport_pic']

            dob = request.form['dob']
            phone = request.form['phone']
            user_id = get_userid()  # Logged in person
            password = generate_random()  # Generate Random Password
            files = request.files.getlist("files[]")
            for file in files:
                if file and allowed_files(file.filename):
                    filename = secure_filename(file.filename)
                    uniquefilename = "{}{}".format(generate_random(), filename)  # add random strings to filename
                    # Upload the file using the random file name.
                    try:
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], uniquefilename))
                        session['uniquefilename'] = uniquefilename
                    except Exception as error:
                        session['uniquefilename'] = ""
                        print("Upload error", error)

                else:
                    return jsonify({"error": "Invalid File, Upload Only png, jpeg, "})

            if not fname:
                return jsonify({'error': 'First name is Empty!'})
            elif not lname:
                return jsonify({'error': 'Last name is Empty!'})
            elif not validate_email(email):
                return jsonify({'error': 'Email is Invalid'})
            elif not dl_no:
                return jsonify({'error': 'dl no is Empty!'})
            elif not dob:
                return jsonify({'error': 'Your DOB is invalid'})
            elif not check_phone(phone):
                return jsonify({'error': 'Invalid Phone use +254XXXXXXXXX'})
            else:
                cursor = connection.cursor()
                sql = '''insert into drivers(fname,lname, surname, phone, email, 
                dl_no,dl_no_expiry,passport_pic,
                loc_id, dob, password, user_id) 
                values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''
                try:
                    cursor.execute(sql, (fname, lname, surname, encrypt(phone), email,
                                         dl_no, dl_no_expiry, session['uniquefilename'], loc_id, dob,
                                         password_hash(password), user_id))
                    connection.commit()
                    message = '''Thank you for Joining FleetS, Download app from link 
                    Login with your email and password: {} To track your Assignments'''.format(password)
                    send_sms(phone, message)
                    return jsonify({'success': 'Driver Added'})
                except:
                    connection.rollback()
                    return jsonify({'error2': 'Driver Not Added'})
        else:
            # get Locations from the database
            locations = getlocations()
            return render_template('admin/adddriver.html', locations=locations)
    else:
        return redirect('/login')


# justpaste.it/9kvae
# This function returns all locations
def getlocations():
    sql = "select * from locations order by loc_name asc"
    cursor = connection.cursor()
    cursor.execute(sql)
    locations = cursor.fetchall()
    return locations


def gettypes():
    sql = "select * from vehicle_types order by type_name asc"
    cursor = connection.cursor()
    cursor.execute(sql)
    types = cursor.fetchall()
    return types


def getmodelList():
    sql = "select * from vehicle_model order by model_name asc"
    cursor = connection.cursor()
    cursor.execute(sql)
    models = cursor.fetchall()
    return models


def getmakes():
    sql = "select * from vehicle_make order by make_name asc"
    cursor = connection.cursor()
    cursor.execute(sql)
    makes = cursor.fetchall()
    return makes


@app.route('/getmodels', methods=['POST', 'GET'])
def getmodels():
    make_id = request.form['make_id']
    sql = "select * from vehicle_model where make_id =%s order by model_name asc"
    cursor = connection.cursor(pymysql.cursors.DictCursor)
    cursor.execute(sql, (make_id))
    models = cursor.fetchall()
    if cursor.rowcount == 0:
        return jsonify({"error": "No Models"})
    else:
        return jsonify(models)


import pymysql.cursors


# ====================get owners =======
@app.route('/ownerlivesearch', methods=['POST', 'GET'])
def ownerlivesearch():
    if check_user() and check_role() == "admin":
        cursor = connection.cursor(pymysql.cursors.DictCursor)
        if request.method == 'POST':
            search_word = request.form['search_word']
            if search_word == '':
                sql = "select * from owners order by owner_id desc"
                cursor.execute(sql)
                owners = cursor.fetchall()
                count = cursor.rowcount
                print(owners)
                return jsonify({'htmlresponse': render_template('views/ownerresponse.html',
                                                                owners=owners, count=count, locations=getlocations())})
            else:
                sql = ''' select * from owners WHERE phone  LIKE '%{}%' or email LIKE '%{}%'  or 
                surname LIKE '%{}%' ORDER BY owner_id DESC  '''.format(search_word, search_word, search_word)
                cursor.execute(sql)
                owners = cursor.fetchall()
                count = cursor.rowcount
                print(owners)
                return jsonify({'htmlresponse': render_template('views/ownerresponse.html',
                                                                owners=owners, count=count,
                                                                locations=getlocations())})
        else:
            return render_template('views/ownerUI.html')
    else:
        return redirect('/login')


@app.route('/driverlivesearch', methods=['POST', 'GET'])
def driverlivesearch():
    if check_user() and check_role() == "admin":
        cursor = connection.cursor(pymysql.cursors.DictCursor)
        if request.method == 'POST':
            search_word = request.form['search_word']
            if search_word == '':
                sql = "select * from drivers order by driver_id desc"
                cursor.execute(sql)
                drivers = cursor.fetchall()
                count = cursor.rowcount
                print(drivers)
                return jsonify({'htmlresponse': render_template('views/driverresponse.html',
                                                                drivers=drivers, count=count,
                                                                locations=getlocations())})
            else:
                sql = ''' select * from drivers WHERE phone  LIKE '%{}%' or email LIKE '%{}%'  or 
                surname LIKE '%{}%' ORDER BY driver_id DESC  '''.format(search_word, search_word, search_word)
                cursor.execute(sql)
                drivers = cursor.fetchall()
                count = cursor.rowcount
                print(drivers)
                return jsonify({'htmlresponse': render_template('views/driverresponse.html',
                                                                drivers=drivers, count=count,
                                                                locations=getlocations())})
        else:
            return render_template('views/driverUI.html')
    else:
        return redirect('/login')


@app.route('/addVehicle/<owner_id>', methods=['POST', 'GET'])
def addVehicle(owner_id):
    # owner id to be encrypted
    if check_user() and check_role() == "admin":
        if request.method == 'POST':
            reg_no = request.form['reg_no']
            type_id = request.form['type_id']
            make_id = request.form['make_id']
            model_id = request.form['model_id']
            capacity_id = request.form['capacity_id']
            color = request.form['color']
            # passport_pic = request.form['passport_pic']
            weight = request.form['weight']
            no_of_pass = request.form['no_of_pass']
            year = request.form['year']
            chassis_no = request.form['chassis_no']
            user_id = get_userid()  # Logged in person
            files = request.files.getlist("files[]")
            for file in files:
                if file and allowed_files(file.filename):
                    filename = secure_filename(file.filename)
                    uniquefilename = "{}{}".format(generate_random(), filename)  # add random strings to filename
                    # Upload the file using the random file name.
                    try:
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], uniquefilename))
                        session['uniquefilename'] = uniquefilename
                    except Exception as error:
                        session['uniquefilename'] = ""
                        print("Upload error", error)

                else:
                    return jsonify({"error": "Invalid File, Upload Only png, jpeg, "})

            if not reg_no:
                return jsonify({'error': 'Reg no is Empty!'})
            elif not chassis_no:
                return jsonify({'error': 'chasis is Empty!'})
            elif not year or len(year) != 4:
                return jsonify({'error': 'Year is Invalid'})
            elif not weight:
                return jsonify({'error': 'Weight is Empty!'})
            elif not color:
                return jsonify({'error': 'Color is Empty'})
            elif not capacity_id:
                return jsonify({'error': 'Capacity'})
            elif not no_of_pass:
                return jsonify({'error': 'No of Pass is Empty'})
            else:
                cursor = connection.cursor()
                sql = '''insert into vehicles(reg_no,type_id, make_id, model_id, 
                capacity_id, color,
                weight,no_of_pass, vehicle_pic, year, owner_id, chassis_no,
                user_id) 
                values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''
                try:
                    cursor.execute(sql, (reg_no, type_id, make_id, model_id, capacity_id,
                                         color, weight, no_of_pass, session['uniquefilename'], year, owner_id,
                                         chassis_no, user_id))
                    connection.commit()
                    sql = "select * from owners where owner_id = %s"
                    cursor = connection.cursor()
                    cursor.execute(sql, (owner_id))
                    row = cursor.fetchone()
                    phone = decrypt(row[4])
                    message = '''Dear {}, Your Vehicle {} Has added to FleetS, Please 
                    Our App on Link to track your Vehicles'''.format(row[1], reg_no)
                    send_sms(phone, message)
                    return jsonify({'success': 'Vehicle Added'})
                except:
                    connection.rollback()
                    return jsonify({'error2': 'Vehicle Not Added'})
        else:
            # get Locations from the database()
            return render_template('admin/addvehicles.html', types=gettypes(),
                                   makes=getmakes(), owner_id=owner_id)
    else:
        return redirect('/login')


@app.route('/viewvehicles/<owner_id>')
def viewvehicles(owner_id):
    if check_user() and check_role() == "admin":
        sql = "select * from vehicles where owner_id = %s"
        cursor = connection.cursor(pymysql.cursors.DictCursor)
        cursor.execute(sql, (owner_id))
        if cursor.rowcount == 0:
            return render_template('views/viewvehicles.html', message="No vehicles")
        else:
            vehicles = cursor.fetchall()
            return render_template('views/viewvehicles.html', vehicles=vehicles,
                                   makes=getmakes(), types=gettypes(), models=getmodelList(),
                                   owner_id=owner_id)
    else:
        return redirect('/login')


@app.route('/vehiclelivesearch/<driver_id>', methods=['POST', 'GET'])
def vehiclelivesearch(driver_id):
    # Put this driver id in session
    if check_user() and check_role() == "admin":
        sqlD = "select * from drivers where driver_id = %s"
        cursor = connection.cursor()
        cursor.execute(sqlD, (driver_id))
        if cursor.rowcount == 0:
            # return to drivers if driver_id does not exist
            return redirect("/driverlivesearch")
        else:
            row = cursor.fetchone()
            phone = decrypt(row[4])
            session['driver_id'] = driver_id
            session['driver_name'] = row[1] + " " + row[2]
            session['phone'] = phone

        cursor = connection.cursor(pymysql.cursors.DictCursor)
        if request.method == 'POST':
            search_word = request.form['search_word']
            if search_word == '':
                sql = "select * from vehicles order by reg_no desc"
                cursor.execute(sql)
                vehicles = cursor.fetchall()
                count = cursor.rowcount
                print(vehicles)
                return jsonify({'htmlresponse': render_template('views/vehicleresponse.html',
                                                                makes=getmakes(), types=gettypes(),
                                                                models=getmodelList(), count=count,
                                                                vehicles=vehicles)})
            else:
                sql = ''' select * from vehicles WHERE reg_no  LIKE '%{}%'
                 ORDER BY reg_no DESC  '''.format(search_word)
                cursor.execute(sql)
                vehicles = cursor.fetchall()
                count = cursor.rowcount
                print(vehicles)
                return jsonify({'htmlresponse': render_template('views/vehicleresponse.html',
                                                                makes=getmakes(), types=gettypes(),
                                                                models=getmodelList(), count=count,
                                                                vehicles=vehicles)})
        else:
            return render_template('views/vehicleUI.html')
    else:
        return redirect('/login')




@app.route('/allocatedriver/<reg_no>')
def allocatedriver(reg_no):
    if check_user() and check_role() == 'admin':
        driver_id = session['driver_id']
        phone = session['phone']
        driver_name = session['driver_name']

        # check double allocation
        sql = "select * from driver_allocations where driver_id = %s and allocation_status = %s"
        cursor = connection.cursor()
        cursor.execute(sql, (driver_id, "active"))

        sql2 = "select * from driver_allocations where reg_no = %s and allocation_status = %s"
        cursor2 = connection.cursor()
        cursor2.execute(sql2, (reg_no, "active"))

        if cursor.rowcount > 0:
            row = cursor.fetchone()
            flash("Driver {} Already Allocated to Vehicle {}".format(driver_name, row[2]), 'alert bg-warning')
            return redirect('/driverlivesearch')

        elif cursor2.rowcount > 0:
            row = cursor2.fetchone()
            flash("Vehicle {} Already Allocated to Driver {}".format(reg_no, row[1]), 'alert bg-warning')
            return redirect('/driverlivesearch')

        else:
            sql = '''insert into driver_allocations(driver_id, reg_no)
            values(%s, %s) '''
            cursor = connection.cursor()
            try:
                cursor.execute(sql, (driver_id, reg_no))
                connection.commit()

                # update
                sqlD = "update drivers set status = %s where driver_id = %s"
                cursorD = connection.cursor()
                cursorD.execute(sqlD, ("Allocated", driver_id))
                connection.commit()

                sqlV = "update vehicles set status = %s where reg_no = %s"
                cursorV = connection.cursor()
                cursorV.execute(sqlV, ("Allocated", reg_no))
                connection.commit()

                message = '''Dear {}, Your have been allocated to Vehicle Reg {}. 
                Thank you'''.format(driver_name, reg_no)
                send_sms(phone, message)
                # Clear driver sessions
                session.pop("driver_id", None)
                session.pop("driver_name", None)
                session.pop("phone", None)

                flash("Success, Driver Allocated", 'alert bg-success')
                return redirect('/driverlivesearch')
            except:
                session.pop("driver_id", None)
                session.pop("driver_name", None)
                session.pop("phone", None)

                connection.rollback()
                flash("Failed! Driver Not Allocated.", 'alert bg-danger')
                return redirect('/driverlivesearch')
    else:
        return redirect('/login')


@app.route('/allocatedvehicle/<driver_id>')
def allocatedvehicle(driver_id):
    if check_user() and check_role() == 'admin':
        sql = "select * from driver_allocations where driver_id = %s and allocation_status =%s"
        cursor = connection.cursor()
        cursor.execute(sql, (driver_id, 'active'))
        row = cursor.fetchone()
        reg_no = row[2] # pull out vehicle reg no

        # query again to find car details
        sql2 = "select * from vehicles where reg_no = %s"
        cursor2 = connection.cursor(pymysql.cursors.DictCursor)
        cursor2.execute(sql2, (reg_no))
        vehicles = cursor2.fetchall()
        return render_template('views/viewvehicles.html', vehicles = vehicles,
                               types = gettypes(), makes = getmakes(),
                               models = getmodelList())
    else:
        return redirect('/login')


app.run(debug=True)
