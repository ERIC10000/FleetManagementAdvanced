
import pymysql
from functions import *
connection = pymysql.connect(host='localhost', user='root',
                             password='', database='FleetDB')

from flask import *
app = Flask(__name__)
app.secret_key = "QGTggg#$$#455_TThh@@ggg_jjj%%&^576" # session ids will be encrypted using this key
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
                        sqlotp = "update users set otp = %s where email = %s"
                        cursor = connection.cursor()
                        cursor.execute(sqlotp, (password_hash(otp), email))
                        connection.commit()
                        cursor.close()
                        # ACTIVATE SESSIONS
                        session['fname'] = row[1] # fname
                        session['role'] = row[5] # role
                        session['user_id'] = row[0] # user_id
                        session['email'] = row[9]   #email
                        return redirect('/confirm_otp') # Move to another route
                    else:
                        return render_template('login.html', message = "Wrong Password")


    else:
        if 'user_id' in session:
            session.clear()
            return render_template('login.html')
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
            otp_hash = row[11]
            status = password_verify(otp, otp_hash)
            if status:
                return redirect('/dashboard') # Two way Auth OK
            else:
                return render_template('confirm_otp.html', message="Wrong OTP")
        else:
             return render_template('confirm_otp.html')

    else:
         return redirect('/login')



app.run(debug=True)