from flask import Flask, flash, render_template, request, redirect, url_for, session
import pyodbc
import hashlib
import time

app = Flask(__name__)
app.secret_key = "?STREENAES21MADEKIMA!"  # Change this to a secure secret key

# Connect to the SQL Server.
# Initialize the database connection
try:
    conn = pyodbc.connect('Driver={SQL Server};'
                          'Server=RG-LPT07\SQLEXPRESS;'
                          'Database=Inventory Project;'
                          'Trusted_Connection=yes;')
    db_status = "Database Connected"
except Exception as e:
    db_status = "Database Connection Failed: " + str(e)

def hash_password(password):

    '''
        Hash the password using sha256.
    '''
    
    return hashlib.sha256(password.encode()).hexdigest()

def getheader(table):
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {table}")
    header = [i[0] for i in cursor.description]
    cursor.close()
    return header


def getdata(table):
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {table}")
    data = cursor.fetchall()
    cursor.close()
    return data

def getdataForUsers():
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM USERS WHERE PRIVEILEGE != 'Admin'")
    data = cursor.fetchall()
    cursor.close()
    return data

def getAuditTrail():
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM AUDIT_TRAIL")
    data = cursor.fetchall()
    cursor.close()
    return data

def sdropDown(table, dropDown):
    cursor = conn.cursor()
    cursor.execute(f"SELECT {dropDown} FROM {table} WHERE Removed = 'F'")
    data = cursor.fetchall() # [(x, ), (y, ), (z, )]
    newdata = [x[0] for x in data] # [x, y, z]
    cursor.close()
    return newdata

def inversesdropDown(table, dropDown):
    cursor = conn.cursor()
    cursor.execute(f"SELECT {dropDown} FROM {table} WHERE Removed = 'T'")
    data = cursor.fetchall() # [(x, ), (y, ), (z, )]
    newdata = [x[0] for x in data] # [x, y, z]
    cursor.close()
    return newdata

def getDropDownForNonAdminUsers():
    cursor = conn.cursor()
    cursor.execute(f"SELECT USERNAME FROM USERS WHERE PRIVEILEGE != 'Admin' AND REMOVED = 'F'")
    data = cursor.fetchall()
    newdata = [x[0] for x in data] # [x, y, z]
    cursor.close()
    return newdata

def getDropDownForNonAdminUsers2():
    cursor = conn.cursor()
    cursor.execute(f"SELECT USERNAME FROM USERS WHERE PRIVEILEGE != 'Admin'")
    data = cursor.fetchall()
    newdata = [x[0] for x in data] # [x, y, z]
    cursor.close()
    return newdata

def get_user_privilege(username):
    cursor = conn.cursor()
    try:
        # Query the USERS table to get the privilege level of the user
        cursor.execute("SELECT PRIVEILEGE FROM USERS WHERE USERNAME = ?", (username,))
        result = cursor.fetchone()
        # print(result[0])
        if result:
            return result[0]  # Assuming the privilege level is in the first column (index 0)
        else:
            return None  # User not found
    except Exception as e:
        # Handle exceptions (e.g., database errors)
        print("Error fetching user privilege:", str(e))
        return None
    finally:
        cursor.close()

def audit_trail_change(username, type, change):
    changed_on = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    cursor = conn.cursor()

    cursor.execute("INSERT INTO AUDIT_TRAIL (USERNAME, TYPE, CHANGE, CHANGED_ON) VALUES (?, ?, ?, ?)", (username, type, change, changed_on))
    cursor.commit()
    cursor.close()

@app.route('/')
def index():
    '''
    index function contains the logic to render the homepage.
    '''
    if 'username' in session:
        # Fetch user information from the database
        cursor = conn.cursor()
        cursor.execute("SELECT USERNAME, PRIVEILEGE FROM USERS WHERE USERNAME = ? AND REMOVED = 'F'", (session['username'],))
        user_info = cursor.fetchone()
        cursor.close()

        if user_info:
            # user_info will be a tuple (USERNAME, PRIVEILEGE)
            username, privilege = user_info
        else:
            # Handle the case where the user is not found in the database
            username, privilege = "User Not Found", "Unknown Privilege"

        return render_template('index.html', username=username, privilege=privilege, db_status=db_status)
    else:
        return redirect(url_for('login'))  # Redirect to the login page if not logged in


@app.route('/login', methods=['GET', 'POST'])
def login():

    '''
        login function handles the /login route.
    '''
    cursor = conn.cursor()
    error_message = None

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        
        # cursor = conn.cursor()
        cursor.execute("SELECT username, password FROM Users WHERE username = ? COLLATE Latin1_General_BIN AND REMOVED = 'F'", username)
        user = cursor.fetchone()

        if user and (user.password == hash_password(password)):
            session['username'] = user.username  # Store the username in the session
            audit_trail_change(username, "Login", "Login Successful")
            return redirect(url_for('index'))
        else:
            audit_trail_change(username, "Login", "Login Failed")
            error_message = "Invalid Credentials. Please Try Again."
    
    cursor.close()
    return render_template('login.html', error_message=error_message)

@app.route('/logout', methods=['GET', 'POST'])
def logout():

    '''
        logout function handles the /logout route.
    '''
    
    if request.method == 'POST':
        audit_trail_change(session.get('username'), "Logout", "Logout Successful")
        session.pop('username', None)
        return redirect(url_for('login'))
    else:
        audit_trail_change(session.get('username'), "Logout", "Logout Successful")
        session.pop('username', None)
        return redirect(url_for('index'))

'''
    Raw Mateiral Functions. All of the flask endpoints below are specific to raw materials.
'''

@app.route('/raw_materials', methods=['GET', 'POST'])
def raw_materials():

    '''
        logout function handles the /logout route.
    '''
    
    if 'username' in session:
        return render_template('raw_materials.html')
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in

# Endpoint for the "Receive" button
@app.route('/receive_rm', methods=['GET', 'POST'])
def receive_raw_material():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('receive_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))
        
        if request.method == 'POST':
            material_name = request.form['material_name']
            quantity_received = request.form['quantity_received']

            # Check if the quantity received is a positive integer
            try:
                quantity_received = int(quantity_received)
                if quantity_received <= 0:
                    flash(("Quantity must be a positive integer.", "info"))
                    return render_template('receive_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))
            except ValueError:
                flash(("Quantity must be a positive integer.", "info"))
                return render_template('receive_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            # Check if the raw material exists
            cursor.execute("SELECT * FROM RAWMATERIALS WHERE NAME = ? AND REMOVED = 'F'", (material_name,))
            raw_material = cursor.fetchone()

            if not raw_material:
                flash(("Material Does Not Exist.", "info"))
            else:
                try:
                    # Update the quantity of the raw material in the database
                    new_quantity = raw_material[4] + quantity_received
                    # print(new_quantity)
                    cursor.execute("UPDATE RAWMATERIALS SET QUANTITY = ? WHERE NAME = ? AND REMOVED = 'F'", (new_quantity, material_name))
                    conn.commit()

                    flash(("Successfully Received {} Units of {} Into Inventory.".format(quantity_received, material_name), "success"))
                    audit_trail_change(session.get('username'), "Recieve RM", "Successfully Received {} Units of {} Into Inventory.".format(quantity_received, material_name))
                except Exception as e:
                    conn.rollback()
                    flash(("Error Receiving Raw Material: {}. Contact IT For Assistance With Raw Materials.".format(str(e)), "error"))
                    audit_trail_change(session.get('username'), "Recieve RM", "Error Receiving Raw Material: {}. Contact IT For Assistance With Raw Materials.".format(str(e)))
                finally:
                    cursor.close()

        return render_template('receive_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in

# Endpoint for the "Use" button
@app.route('/use_rm', methods=['GET', 'POST'])
def use_raw_material():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('use_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))

        if request.method == 'POST':
            material_name = request.form['material_name']
            quantity_used = request.form['quantity_used']

            # Check if the quantity used is a positive integer
            try:
                quantity_used = int(quantity_used)
                if quantity_used <= 0:
                    flash(("Quantity must be a positive integer.", "info"))
                    return render_template('use_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))
            except ValueError:
                flash(("Quantity must be a positive integer.", "info"))
                return render_template('use_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            # Check if the raw material exists
            cursor.execute("SELECT * FROM RAWMATERIALS WHERE NAME = ? AND REMOVED = 'F'", (material_name,))
            raw_material = cursor.fetchone()

            if not raw_material:
                flash(("Material Does Not Exist.", "info"))
            else:
                try:
                    current_quantity = raw_material[4]
                    
                    # Check if there is enough quantity to use
                    if current_quantity >= quantity_used:
                        new_quantity = current_quantity - quantity_used
                        cursor.execute("UPDATE RAWMATERIALS SET QUANTITY = ? WHERE NAME = ? AND REMOVED = 'F'", (new_quantity, material_name))
                        conn.commit()

                        flash(("Successfully Used {} Units of {}.".format(quantity_used, material_name), "success"))

                        audit_trail_change(session.get('username'), "Use RM", "Successfully Used {} Units of {}.".format(quantity_used, material_name))
                    else:
                        audit_trail_change(session.get('username'), "Use RM", "Insufficient quantity of {} available.".format(material_name))
                        flash(("Insufficient quantity of {} available.".format(material_name), "info"))

                except Exception as e:
                    conn.rollback()
                    flash(("Error Using Raw Material: {}. Contact IT For Assistance With Raw Materials.".format(str(e)), "error"))
                    audit_trail_change(session.get('username'), "Use RM", "Error Using Raw Material: {}. Contact IT For Assistance With Raw Materials.".format(str(e)))
                finally:
                    cursor.close()

        return render_template('use_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in


# Endpoint for the "Adjust" button
@app.route('/adjust_rm', methods=['GET', 'POST'])
def adjust_raw_material():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('adjust_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))
        
        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function
        if user_privilege not in ['Admin', 'Manager']:
            flash(("You As A {} Do Not Have The Required Privileges To Perform This Action Ask A Manager.".format(user_privilege), "info"))
            return render_template('adjust_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))
        
        if request.method == 'POST':
            material_name = request.form['material_name']
            new_quantity = request.form['new_quantity']

            # Check if the new quantity is a positive integer
            try:
                new_quantity = int(new_quantity)
                if new_quantity < 0:
                    flash(("New quantity cannot be negative.", "info"))
                    return render_template('adjust_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))
            except ValueError:
                flash(("New quantity must be a positive integer.", "info"))
                return render_template('adjust_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            # Check if the raw material exists
            cursor.execute("SELECT * FROM RAWMATERIALS WHERE NAME = ? AND REMOVED = 'F'", (material_name,))
            raw_material = cursor.fetchone()

            if not raw_material:
                flash(("Material Does Not Exist.", "info"))
            else:
                try:
                    cursor.execute("UPDATE RAWMATERIALS SET QUANTITY = ? WHERE NAME = ? AND REMOVED = 'F'", (new_quantity, material_name))
                    conn.commit()

                    flash(("Successfully Adjusted Quantity of {} to {}.".format(material_name, new_quantity), "success"))
                    audit_trail_change(session.get('username'), "Adjust RM", "Successfully Adjusted Quantity of {} to {}.".format(material_name, new_quantity))
                except Exception as e:
                    conn.rollback()
                    flash(("Error Adjusting Raw Material Quantity: {}. Contact IT For Assistance With Raw Materials.".format(str(e)), "error"))
                    audit_trail_change(session.get('username'), "Adjust RM", "Error Adjusting Raw Material Quantity: {}. Contact IT For Assistance With Raw Materials.".format(str(e)))
                finally:
                    cursor.close()

        return render_template('adjust_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in


# Endpoint for the "Add New Entry" button
@app.route('/add_new_rm', methods=['GET', 'POST'])
def add_new_raw_material():
    associated_code_DNE = False
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('add_new_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), units=sdropDown('UNITS_RM', 'NAME'))
        
        if request.method == 'POST':
            material_name = request.form['material_name']
            units = request.form['units']
            quantity = int(request.form['quantity'])
            cost = float(request.form.get('cost'))
            associated_codes = request.form.get('associated_codes', '')  # Optional field, default to an empty string

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            if quantity < 0 or cost < 0:
                flash(("Do Not Insert Negative Values", "info"))
                return render_template('add_new_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), units=sdropDown('UNITS_RM', 'NAME'))

            try:
                cursor.execute("SELECT * FROM RAWMATERIALS WHERE NAME = ?", (material_name,))
                checkUnit = cursor.fetchone()

                if checkUnit:
                    flash(("Material '{}' Already Exists".format(material_name), "info"))
                    return render_template('add_new_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), units=sdropDown('UNITS_RM', 'NAME'))


                if associated_codes:
                    # Split the associated codes into a list and remove leading/trailing spaces
                    associated_codes_list = [code.strip() for code in associated_codes.split(',')]
                    for code in associated_codes_list:
                        cursor.execute("SELECT * FROM FINISHEDPRODUCT WHERE CODE = ? AND REMOVED = 'F'", (code.strip(),))
                        checkExistCode = cursor.fetchone()

                        if (not checkExistCode):
                            flash(("One Of The Product Codes Does Not Exist", "info"))
                            return render_template('add_new_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), units=sdropDown('UNITS_RM', 'NAME'))

                if associated_codes:
                    # Split the associated codes into a list and remove leading/trailing spaces
                    associated_codes_list = [code.strip() for code in associated_codes.split(',')]

                    # Check for duplicates in associated codes
                    if len(associated_codes_list) != len(set(associated_codes_list)):
                        flash(("Duplicate Associated Codes Found", "info"))
                        return render_template('add_new_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), units=sdropDown('UNITS_RM', 'NAME'))

                    # Convert the list back to a comma-separated string
                    associated_codes_str = ', '.join(associated_codes_list)
                else:
                    associated_codes_str = ''

                # Insert the associated codes into the database
                cursor.execute("INSERT INTO RAWMATERIALS (NAME, COST, UNITS, QUANTITY, ASSOCIATED_CODES, REMOVED) VALUES (?, ?, ?, ?, ?, ?)",
                                (material_name, cost, units, quantity, associated_codes_str, 'F'))
                conn.commit()
    
                # Retrieve the MATERIALID of the newly inserted raw material
                cursor.execute("SELECT MATERIALID FROM RAWMATERIALS WHERE NAME = ?", (material_name,))
                raw_material_id = cursor.fetchone()[0]  # Access the first column which contains 'MATERIALID'

                # print(raw_material_id)
                if raw_material_id > 0:
                    flash(("Raw Material Added Successfully", "success"))

                    associated_codes_inserted = False  # Track whether associated codes were successfully inserted

                    # Check if associated codes are provided
                    if associated_codes:
                        # Split associated codes by comma and insert into RAWMATERIALASSOCIATION table
                        for code in associated_codes.split(','):
                            cursor.execute("SELECT * FROM RAWMATERIALASSOCIATION WHERE RAWMATERIALID = ? AND CODE = ?",
                                            (raw_material_id, code.strip()))
                            check_association = cursor.fetchone()
                            
                            # Check if the association doesn't exist, then insert it
                            if not check_association:
                                # print(code.strip())
                                cursor.execute("INSERT INTO RAWMATERIALASSOCIATION (RAWMATERIALID, CODE) VALUES (?, ?)",
                                                (raw_material_id, code.strip()))
                                conn.commit()
                                
                                # Verify the association again after insertion
                                cursor.execute("SELECT * FROM RAWMATERIALASSOCIATION WHERE RAWMATERIALID = ? AND CODE = ?",
                                                (raw_material_id, code.strip()))
                                check_association = cursor.fetchone()

                                if not check_association:
                                    flash(("Error Adding Association for Code: " + code.strip(), "info"))
                                    return render_template('add_new_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), units=sdropDown('UNITS_RM', 'NAME'))
                                else:
                                    flash(("Raw Material And Associated Codes Added Successfully", "success"))
                            else:
                                flash(("Duplicate Associated Codes Found", "info"))
                                return render_template('add_new_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), units=sdropDown('UNITS_RM', 'NAME'))


                        # if cursor.rowcount > 0:
                        #     associated_codes_inserted = True
                        #     flash(("Associated Codes Added Successfully", "success"))
                        # else:
                        #     flash(("Associated Codes Not Added. Please Check The Input.", "info"))

                    # Check associated_codes_inserted to determine whether to display a success message for the second insertion
                    if not associated_codes or associated_codes_inserted:
                        flash(("Raw Material And Associated Codes Added Successfully", "success"))
                        audit_trail_change(session.get('username'), "Add New RM", "Successfully Inserted {}, and associated to {}".format(material_name, associated_codes_str))
                else:
                    flash(("Raw Material Not Added. Please Check The Input.", "info"))
                    audit_trail_change(session.get('username'), "Add New RM", "Failed to Add {}, and associated to {}".format(material_name, associated_codes_str))

            except Exception as e:
                conn.rollback()
                flash(("Error Adding Raw Material: " + str(e) + " Contact IT database error for restoring Raw Materials in table RAWMATERIALS", "error"))
                audit_trail_change(session.get('username'), "Add New RM", "Error Adding Raw Material: " + str(e) + " Contact IT database error for restoring Raw Materials in table RAWMATERIALS")
            finally:
                cursor.close()

        return render_template('add_new_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), units=sdropDown('UNITS_RM', 'NAME'))
    else:
        return redirect(url_for('login'))  # Redirect to the login page if not logged in



# Endpoint for the "Delete Existing Entry" button
@app.route('/delete_existing_rm', methods=['GET', 'POST'])
def delete_existing_raw_material_entry():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('delete_existing_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))
        
        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function
        if user_privilege not in ['Admin', 'Manager']:
            flash(("You As A {} Do Not Have The Required Privileges To Perform This Action Ask A Manager.".format(user_privilege), "info"))
            return render_template('delete_existing_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))

        if request.method == 'POST':
            # Get the material name to be deleted from the form
            material_name_to_delete = request.form['material_name']

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            try:
                # Check if the material exists
                cursor.execute("SELECT * FROM RAWMATERIALS WHERE NAME = ? AND REMOVED = 'F'", (material_name_to_delete,))
                existing_material = cursor.fetchone()

                if not existing_material:
                    flash(("Material Not Found", "info"))
                else:
                    # Implement code to delete the material (soft delete)
                    cursor.execute("UPDATE RAWMATERIALS SET REMOVED = 'T' WHERE NAME = ?", (material_name_to_delete,))
                    conn.commit()

                    if cursor.rowcount > 0:
                        flash(("Raw Material Deleted Successfully", "success"))
                        audit_trail_change(session.get('username'), "Remove RM", "Raw Material {} Deleted Successfully".format(material_name_to_delete))
                    else:
                        flash(("Raw Material Not Deleted. Please Check The Input.", "info"))
                        audit_trail_change(session.get('username'), "Remove RM", "Raw Material {} Not Deleted. Please Check The Input.".format(material_name_to_delete))

            except Exception as e:
                conn.rollback()
                flash(("Error Deleting Raw Material: " + str(e) + "Contact IT database error for restoring Raw Materials in table RAWMATERIALS Table & its Dependencies", "error"))
                audit_trail_change(session.get('username'), "Remove RM", "Error Deleting Raw Material: " + str(e) + "Contact IT database error for restoring Raw Materials in table RAWMATERIALS Table & its Dependencies")
            finally:
                cursor.close()

        return render_template('delete_existing_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in

# Endpoint for the "Delete Existing Entry" button
@app.route('/restore_existing_rm', methods=['GET', 'POST'])
def restore_existing_raw_material_entry():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('restore_existing_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=inversesdropDown('RAWMATERIALS', 'NAME'))
        
        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function
        if user_privilege not in ['Admin', 'Manager']:
            flash(("You As A {} Do Not Have The Required Privileges To Perform This Action Ask A Manager.".format(user_privilege), "info"))
            return render_template('restore_existing_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=inversesdropDown('RAWMATERIALS', 'NAME'))
        
        if request.method == 'POST':
            # Get the material name to be deleted from the form
            material_name_to_restore = request.form['material_name']

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            try:
                # Check if the material exists
                cursor.execute("SELECT * FROM RAWMATERIALS WHERE NAME = ?  AND REMOVED = 'T'", (material_name_to_restore,))
                existing_material = cursor.fetchone()

                if not existing_material:
                    flash(("Material Not Found", "info"))
                else:
                    # Implement code to restore the material (soft restore)
                    cursor.execute("UPDATE RAWMATERIALS SET REMOVED = 'F' WHERE NAME = ?", (material_name_to_restore,))
                    conn.commit()

                    if cursor.rowcount > 0:
                        flash(("Raw Material Restored Successfully", "success"))
                        audit_trail_change(session.get('username'), "Restore RM", "Raw Material {} Restored Successfully".format(material_name_to_restore))
                    else:
                        flash(("Raw Material Not Restored. Please Check The Input.", "info"))
                        audit_trail_change(session.get('username'), "Restore RM", "Raw Material {} Not Restored".format(material_name_to_restore))

            except Exception as e:
                conn.rollback()
                flash(("Error Restoring Raw Material: " + str(e) + "Contact IT database error for restoring Raw Mateirals in table RAWMATERIALS Table & its Dependencies", "error"))
            finally:
                cursor.close()

        return render_template('restore_existing_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=inversesdropDown('RAWMATERIALS', 'NAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in
    

# Endpoint for the "Update Associations" button
@app.route('/update_associations_rm', methods=['GET', 'POST'])
def update_associations_raw_material():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('update_associations_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))
        

        if request.method == 'POST':
            material_name = request.form['material_name']
            operation = request.form['operation']  # Add or Delete
            associated_codes = request.form.get('associated_codes', '')  # Optional field, default to an empty string

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            try:
                # Check if the material exists
                cursor.execute("SELECT MATERIALID, ASSOCIATED_CODES FROM RAWMATERIALS WHERE NAME = ? AND REMOVED = 'F'", (material_name,))
                raw_material_data = cursor.fetchone()

                if not raw_material_data:
                    flash(("Material Not Found", "info"))
                else:
                    raw_material_id = raw_material_data[0]
                    current_associated_codes = raw_material_data[1]

                    # Initialize current_associated_codes_list before the loop
                    current_associated_codes_list = current_associated_codes.split(', ')

                    if operation == 'Add':
                        if associated_codes:
                            # Split the associated codes into a list and remove leading/trailing spaces
                            associated_codes_list = [code.strip() for code in associated_codes.split(',')]

                            # Check for duplicates in associated codes
                            if len(associated_codes_list) != len(set(associated_codes_list)):
                                flash(("Duplicate Associated Codes Found", "info"))
                            else:
                                # Initialize a list to keep track of new associations
                                new_associated_codes_list = current_associated_codes_list.copy()
                                
                                # Insert new associations and update the new_associated_codes_list
                                for code in associated_codes_list:
                                    # Check if the product code exists
                                    cursor.execute("SELECT * FROM FINISHEDPRODUCT WHERE CODE = ? AND REMOVED = 'F'", (code,))
                                    check_exist_code = cursor.fetchone()

                                    if not check_exist_code:
                                        flash(("Product Code {} Does Not Exist".format(code), "info"))
                                        return render_template('update_associations_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))

                                    # Check if the association already exists
                                    cursor.execute("SELECT * FROM RAWMATERIALASSOCIATION WHERE RAWMATERIALID = ? AND CODE = ?", (raw_material_id, code))
                                    check_association = cursor.fetchone()

                                    if check_association:
                                        flash(("Association for Product Code {} Already Exists".format(code), "info"))
                                        return render_template('update_associations_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))

                                    # Insert the new association
                                    cursor.execute("INSERT INTO RAWMATERIALASSOCIATION (RAWMATERIALID, CODE) VALUES (?, ?)", (raw_material_id, code))
                                    conn.commit()

                                    # Update the new_associated_codes_list
                                    if code not in new_associated_codes_list:
                                        new_associated_codes_list.append(code)

                                # Join the updated new_associated_codes_list and update the associated_codes column
                                if new_associated_codes_list:  # Check if the list is not empty and not None
                                    new_associated_codes_str = ', '.join(new_associated_codes_list)
                                else:
                                    new_associated_codes_str = ''  # Set it to an empty string if the list is empty or None


                                cursor.execute("UPDATE RAWMATERIALS SET ASSOCIATED_CODES = ? WHERE MATERIALID = ?", (new_associated_codes_str, raw_material_id))
                                conn.commit()

                                flash(("Associations Added Successfully", "success"))
                                audit_trail_change(session.get('username'), "Update Associations RM", "Associations {} Added Successfully to {}".format(new_associated_codes_str, material_name))

                        else:
                            flash(("No Associations Provided", "info"))

                    elif operation == 'Delete':
                        if associated_codes:
                            # Split the associated codes into a list and remove leading/trailing spaces
                            associated_codes_list = [code.strip() for code in associated_codes.split(',')]

                            # Check if the associations to be deleted exist
                            for code in associated_codes_list:
                                # Check if the association exists
                                cursor.execute("SELECT * FROM RAWMATERIALASSOCIATION WHERE RAWMATERIALID = ? AND CODE = ?",
                                            (raw_material_id, code))
                                check_association = cursor.fetchone()

                                if not check_association:
                                    flash(("Association for Product Code {} Does Not Exist".format(code), "info"))
                                    return render_template('update_associations_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))

                            # Delete the specified associations
                            for code in associated_codes_list:
                                cursor.execute("DELETE FROM RAWMATERIALASSOCIATION WHERE RAWMATERIALID = ? AND CODE = ?",
                                            (raw_material_id, code))
                                conn.commit()

                            # Update the associated_codes column in RAWMATERIALS
                            current_associated_codes_list = [c for c in current_associated_codes_list if c not in associated_codes_list]
                            updated_associated_codes_str = ', '.join(current_associated_codes_list)
                            cursor.execute("UPDATE RAWMATERIALS SET ASSOCIATED_CODES = ? WHERE MATERIALID = ?",
                                        (updated_associated_codes_str, raw_material_id))
                            conn.commit()

                            flash(("Associations Deleted Successfully", "success"))
                            audit_trail_change(session.get('username'),  "Update Associations RM", "Associations {} Removed Successfully to {}".format(new_associated_codes_str, material_name))
                        else:
                            flash(("No Associations Provided for Deletion", "info"))


            except Exception as e:
                conn.rollback()
                flash(("Error Updating Associations: " + str(e), "error"))
            finally:
                cursor.close()

        return render_template('update_associations_rm.html', headers=getheader('RAWMATERIALS'), data=getdata('RAWMATERIALS'), material_names=sdropDown('RAWMATERIALS', 'NAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in


# Endpoint for the "Manage Units" page

@app.route('/manage_units', methods=['GET', 'POST'])
def manage_units():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('manage_units.html', header=getheader('UNITS_RM'), data=getdata('UNITS_RM'), units=sdropDown('UNITS_RM', 'NAME'))
        

        if request.method == 'POST':
            unit_name = request.form['unit_name']
            action = request.form['action']
            
            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            # Perform the action (add, delete, or restore) based on the user's choice
            if action == 'add':
                try:

                    cursor.execute("SELECT * FROM UNITS_RM WHERE NAME = ?", (unit_name,))
                    checkUnit = cursor.fetchone()

                    if (checkUnit):
                        flash(("Unit '{}' Already Exists (Check Removed & Existing Units)".format(unit_name), "info"))
                        return render_template('manage_units.html', header=getheader('UNITS_RM'), data=getdata('UNITS_RM'), units=sdropDown('UNITS_RM', 'NAME'))
                                    
                    # Implement code to add the unit to the database
                    cursor.execute("INSERT INTO UNITS_RM (NAME, REMOVED) VALUES (?, ?)", (unit_name, 'F'))
                    conn.commit()
                    if cursor.rowcount > 0:
                        flash(("Unit '{}' Added Successfully".format(unit_name), "success"))
                        audit_trail_change(session.get('username'), "Manage Units RM", "Unit '{}' Added Successfully".format(unit_name))
                    else:
                        flash(("Unit '{}' Not Added. Please Check The Input.".format(unit_name), "info"))
                except Exception as e:
                    conn.rollback()
                    flash(("Error Adding Unit: " + str(e) + " Contact IT Database Error For Adding Units in Table UNIT_RM", "error"))
                    audit_trail_change(session.get('username'), "Manage Units RM", "Error Adding Unit: " + str(e) + " Contact IT Database Error For Adding Units in Table UNIT_RM")
                finally:
                    cursor.close()
            elif action == 'delete':
                try:                    
                    # Implement code to delete the unit from the database (soft delete)
                    cursor.execute("UPDATE UNITS_RM SET REMOVED = 'T' WHERE NAME = ? AND REMOVED = 'F'", (unit_name,))
                    conn.commit()
                    if cursor.rowcount > 0:
                        flash(("Unit '{}' Deleted Successfully".format(unit_name), "success"))
                        audit_trail_change(session.get('username'), "Manage Units RM", "Unit '{}' Deleted Successfully".format(unit_name))
                    else:
                        flash(("Unit '{}' Not Found or Not Deleted. Please Check The Input.".format(unit_name), "info"))
                except Exception as e:
                    conn.rollback()
                    flash(("Error Deleting Unit: " + str(e) + " Contact IT Database Error For Adding Units in Table UNIT_RM", "error"))
                    audit_trail_change(session.get('username'), "Manage Units RM", "Error Deleting Unit: " + str(e) + " Contact IT Database Error For Adding Units in Table UNIT_RM")
                finally:
                    cursor.close()
            elif action == 'restore':
                try:
                    # Implement code to restore the unit in the database
                    cursor.execute("UPDATE UNITS_RM SET REMOVED = 'F' WHERE NAME = ? AND REMOVED = 'T'", (unit_name,))
                    conn.commit()
                    if cursor.rowcount > 0:
                        flash(("Unit '{}' Restored Successfully".format(unit_name), "success"))
                        audit_trail_change(session.get('username'), "Manage Units RM", "Unit '{}' Restored Successfully".format(unit_name))
                    else:
                        flash(("Unit '{}' Not Found or Not Restored. Please Check The Input.".format(unit_name), "info"))
                except Exception as e:
                    conn.rollback()
                    flash(("Error Restoring Unit: " + str(e) + "Contact IT database error for restoring units in table UNIT_RM", "error"))
                    audit_trail_change(session.get('username'), "Manage Units RM", "Error Restoring Unit: " + str(e) + "Contact IT database error for restoring units in table UNIT_RM")
                finally:
                    cursor.close()

        return render_template('manage_units.html', header=getheader('UNITS_RM'), data=getdata('UNITS_RM'), units=sdropDown('UNITS_RM', 'NAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in


'''
    Packaging Mateiral Functions. All of the flask endpoints below are specific to packaging materials.
'''

@app.route('/packaging_materials', methods=['GET', 'POST'])
def packaging_materials():

    '''
        packaging_materials function handles the /packaging_materials route.
    '''
    
    if 'username' in session:
        return render_template('packaging_materials.html')
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in

# Endpoint for the "Receive" button
@app.route('/receive_pm', methods=['GET', 'POST'])
def receive_packaging_material():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('receive_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))
        

        if request.method == 'POST':
            material_name = request.form['material_name']
            quantity_received = int(request.form['quantity_received'])

            # Check if the quantity received is a positive integer
            try:
                quantity_received = int(quantity_received)
                if quantity_received <= 0:
                    flash(("Quantity must be a positive integer.", "info"))
                    return render_template('receive_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))
            except ValueError:
                flash(("Quantity must be a positive integer.", "info"))
                return render_template('receive_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            # Check if the raw material exists
            cursor.execute("SELECT * FROM PACKAGINGMATERIALS WHERE NAME = ? AND REMOVED = 'F'", (material_name,))
            packaging_material = cursor.fetchone()

            if not packaging_material:
                flash(("Material Does Not Exist.", "info"))
            else:
                try:
                    # Update the quantity of the raw material in the database
                    new_quantity = packaging_material[3] + quantity_received
                    # print(new_quantity)
                    cursor.execute("UPDATE PACKAGINGMATERIALS SET QUANTITY = ? WHERE NAME = ? AND REMOVED = 'F'", (new_quantity, material_name))
                    conn.commit()

                    flash(("Successfully Received {} Units of {} Into Inventory.".format(quantity_received, material_name), "success"))
                    audit_trail_change(session.get('username'), "Receive PM", "Successfully Received {} Units of {} Into Inventory.".format(quantity_received, material_name))

                except Exception as e:
                    conn.rollback()
                    flash(("Error Receiving Packaging Material: {}. Contact IT For Assistance With Packaging Materials in PACKAGINGMATERIALS Table.".format(str(e)), "error"))
                    audit_trail_change(session.get('username'), "Receive PM", "Error Receiving Packaging Material: {}. Contact IT For Assistance With Packaging Materials in PACKAGINGMATERIALS Table.".format(str(e)))
                finally:
                    cursor.close()

        return render_template('receive_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in

# Endpoint for the "Use" button
@app.route('/use_pm', methods=['GET', 'POST'])
def use_packaging_material():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('use_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))
        
        if request.method == 'POST':
            material_name = request.form['material_name']
            quantity_used = request.form['quantity_used']

            # Check if the quantity used is a positive integer
            try:
                quantity_used = int(quantity_used)
                if quantity_used <= 0:
                    flash(("Quantity must be a positive integer.", "info"))
                    return render_template('use_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))
            except ValueError:
                flash(("Quantity must be a positive integer.", "info"))
                return render_template('use_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            # Check if the raw material exists
            cursor.execute("SELECT * FROM PACKAGINGMATERIALS WHERE NAME = ? AND REMOVED = 'F'", (material_name,))
            packaging_material = cursor.fetchone()

            if not packaging_material:
                flash(("Material Does Not Exist.", "info"))
            else:
                try:
                    current_quantity = packaging_material[3]
                    
                    # Check if there is enough quantity to use
                    if current_quantity >= quantity_used:
                        new_quantity = current_quantity - quantity_used
                        cursor.execute("UPDATE PACKAGINGMATERIALS SET QUANTITY = ? WHERE NAME = ? AND REMOVED = 'F'", (new_quantity, material_name))
                        conn.commit()

                        flash(("Successfully Used {} Units of {}.".format(quantity_used, material_name), "success"))
                        audit_trail_change(session.get('username'), "Use PM", "Successfully Used {} Units of {}.".format(quantity_used, material_name))
                    else:
                        flash(("Insufficient quantity of {} available.".format(material_name), "info"))

                except Exception as e:
                    conn.rollback()
                    flash(("Error Using Packaging Material: {}. Contact IT For Assistance With Packaging Materials in PACKAGINGMATERIALS Table.".format(str(e)), "error"))
                    audit_trail_change(session.get('username'), "Use PM", "Error Using Packaging Material: {}. Contact IT For Assistance With Packaging Materials in PACKAGINGMATERIALS Table.".format(str(e)))
                finally:
                    cursor.close()

        return render_template('use_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in


# Endpoint for the "Adjust" button
@app.route('/adjust_pm', methods=['GET', 'POST'])
def adjust_packaging_material():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('adjust_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))
        
        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function
        if user_privilege not in ['Admin', 'Manager']:
            flash(("You As A {} Do Not Have The Required Privileges To Perform This Action Ask A Manager.".format(user_privilege), "info"))
            return render_template('adjust_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))
        
        if request.method == 'POST':
            material_name = request.form['material_name']
            new_quantity = request.form['new_quantity']

            # Check if the new quantity is a positive integer
            try:
                new_quantity = int(new_quantity)
                if new_quantity < 0:
                    flash(("New quantity cannot be negative.", "info"))
                    return render_template('adjust_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))
            except ValueError:
                flash(("New quantity must be a positive integer.", "info"))
                return render_template('adjust_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            # Check if the raw material exists
            cursor.execute("SELECT * FROM PACKAGINGMATERIALS WHERE NAME = ? AND REMOVED = 'F'", (material_name,))
            packaging_material = cursor.fetchone()

            if not packaging_material:
                flash(("Material Does Not Exist.", "info"))
            else:
                try:
                    cursor.execute("UPDATE PACKAGINGMATERIALS SET QUANTITY = ? WHERE NAME = ? AND REMOVED = 'F'", (new_quantity, material_name))
                    conn.commit()

                    flash(("Successfully Adjusted Quantity of {} to {}.".format(material_name, new_quantity), "success"))
                    audit_trail_change(session.get('username'), "Adjust PM", "Successfully Adjusted Quantity of {} to {}.".format(material_name, new_quantity))
                except Exception as e:
                    conn.rollback()
                    flash(("Error Adjusting Packaging Material Quantity: {}. Contact IT For Assistance With Packaging Materials.".format(str(e)), "error"))
                    audit_trail_change(session.get('username'), "Adjust PM", "Error Adjusting Packaging Material Quantity: {}. Contact IT For Assistance With Packaging Materials.".format(str(e)))
                finally:
                    cursor.close()

        return render_template('adjust_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in
    

# Endpoint for the "Add New Entry" button
@app.route('/add_new_pm', methods=['GET', 'POST'])
def add_new_packaging_material():
    associated_code_DNE = False
    
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('add_new_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'))
        
        if request.method == 'POST':
            material_name = request.form['material_name']
            quantity = int(request.form['quantity'])
            cost = float(request.form.get('cost'))
            associated_codes = request.form.get('associated_codes', '')  # Optional field, default to an empty string

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            if quantity < 0 or cost < 0:
                flash(("Do Not Insert Negative Values", "info"))
                return render_template('add_new_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'))

            try:
                cursor.execute("SELECT * FROM PACKAGINGMATERIALS WHERE NAME = ?", (material_name,))
                checkUnit = cursor.fetchone()

                if checkUnit:
                    flash(("Material '{}' Already Exists".format(material_name), "info"))
                    return render_template('add_new_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'))


                if associated_codes:
                    # Split the associated codes into a list and remove leading/trailing spaces
                    associated_codes_list = [code.strip() for code in associated_codes.split(',')]
                    for code in associated_codes_list:
                        cursor.execute("SELECT * FROM FINISHEDPRODUCT WHERE CODE = ? AND REMOVED = 'F'", (code.strip(),))
                        checkExistCode = cursor.fetchone()

                        if (not checkExistCode):
                            flash(("One Of The Product Codes Does Not Exist", "info"))
                            return render_template('add_new_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'))

                if associated_codes:
                    # Split the associated codes into a list and remove leading/trailing spaces
                    associated_codes_list = [code.strip() for code in associated_codes.split(',')]

                    # Check for duplicates in associated codes
                    if len(associated_codes_list) != len(set(associated_codes_list)):
                        flash(("Duplicate Associated Codes Found", "info"))
                        return render_template('add_new_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'))

                    # Convert the list back to a comma-separated string
                    associated_codes_str = ', '.join(associated_codes_list)
                else:
                    associated_codes_str = ''

                # Insert the associated codes into the database
                cursor.execute("INSERT INTO PACKAGINGMATERIALS (NAME, COST, QUANTITY, ASSOCIATED_CODES, REMOVED) VALUES (?, ?, ?, ?, ?)",
                                (material_name, cost, quantity, associated_codes_str, 'F'))
                conn.commit()

                # Retrieve the MATERIALID of the newly inserted raw material
                cursor.execute("SELECT MATERIALID FROM PACKAGINGMATERIALS WHERE NAME = ?", (material_name,))
                raw_material_id = cursor.fetchone()[0]  # Access the first column which contains 'MATERIALID'

                # print(raw_material_id)
                if raw_material_id > 0:
                    flash(("Packaging Material Added Successfully", "success"))

                    associated_codes_inserted = False  # Track whether associated codes were successfully inserted

                    # Check if associated codes are provided
                    if associated_codes:
                        # Split associated codes by comma and insert into PACKAGINGMATERIALASSOCIATION table
                        for code in associated_codes.split(','):
                            cursor.execute("SELECT * FROM PACKAGINGMATERIALASSOCIATION WHERE PACKAGINGMATERIALID = ? AND CODE = ?",
                                            (raw_material_id, code.strip()))
                            check_association = cursor.fetchone()
                            
                            # Check if the association doesn't exist, then insert it
                            if not check_association:
                                print(code.strip())
                                cursor.execute("INSERT INTO PACKAGINGMATERIALASSOCIATION (PACKAGINGMATERIALID, CODE) VALUES (?, ?)",
                                                (raw_material_id, code.strip()))
                                conn.commit()
                                
                                # Verify the association again after insertion
                                cursor.execute("SELECT * FROM PACKAGINGMATERIALASSOCIATION WHERE PACKAGINGMATERIALID = ? AND CODE = ?",
                                                (raw_material_id, code.strip()))
                                check_association = cursor.fetchone()

                                if not check_association:
                                    flash(("Error Adding Association for Code: " + code.strip(), "info"))
                                    return render_template('add_new_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'))
                                else:
                                    flash(("Packaging Material And Associated Codes Added Successfully", "success"))
                            else:
                                flash(("Duplicate Associated Codes Found", "info"))
                                return render_template('add_new_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'))


                        # if cursor.rowcount > 0:
                        #     associated_codes_inserted = True
                        #     flash(("Associated Codes Added Successfully", "success"))
                        # else:
                        #     flash(("Associated Codes Not Added. Please Check The Input.", "info"))

                    # Check associated_codes_inserted to determine whether to display a success message for the second insertion
                    if not associated_codes or associated_codes_inserted:
                        flash(("Packaging Material And Associated Codes Added Successfully", "success"))
                        audit_trail_change(session.get('username'), "Add New PM", "Successfully Added {} and Associated to {}.".format(material_name, associated_codes))
                else:
                    flash(("Packaging Material Not Added. Please Check The Input.", "info"))

            except Exception as e:
                conn.rollback()
                flash(("Error Adding Packaging Material: " + str(e) + " Contact IT Database Error For Restoring Packaging Materials in table PACKAGINGMATERIALS", "error"))
                audit_trail_change(session.get('username'), "Add New PM", "Error Adding Packaging Material: " + str(e) + " Contact IT Database Error For Restoring Packaging Materials in table PACKAGINGMATERIALS")
            finally:
                cursor.close()

        return render_template('add_new_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'))
    else:
        return redirect(url_for('login'))  # Redirect to the login page if not logged in

# Endpoint for the "Delete Existing Entry" button
@app.route('/delete_existing_pm', methods=['GET', 'POST'])
def delete_existing_packaging_material_entry():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('delete_existing_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))
        
        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function
        if user_privilege not in ['Admin', 'Manager']:
            flash(("You As A {} Do Not Have The Required Privileges To Perform This Action Ask A Manager.".format(user_privilege), "info"))
            return render_template('delete_existing_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))

        if request.method == 'POST':
            # Get the material name to be deleted from the form
            material_name_to_delete = request.form['material_name']

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            try:
                # Check if the material exists
                cursor.execute("SELECT * FROM PACKAGINGMATERIALS WHERE NAME = ? AND REMOVED = 'F'", (material_name_to_delete,))
                existing_material = cursor.fetchone()

                if not existing_material:
                    flash(("Material Not Found", "info"))
                else:
                    # Implement code to delete the material (soft delete)
                    cursor.execute("UPDATE PACKAGINGMATERIALS SET REMOVED = 'T' WHERE NAME = ?", (material_name_to_delete,))
                    conn.commit()

                    if cursor.rowcount > 0:
                        flash(("Packaging Material Deleted Successfully", "success"))
                        audit_trail_change(session.get('username'), "Delete PM", "Packaging Material {} Deleted Successfully.".format(material_name_to_delete))
                    else:
                        flash(("Packaging Material Not Deleted. Please Check The Input.", "info"))
                        audit_trail_change(session.get('username'), "Delete PM", "Packaging Material {} Not Deleted.".format(material_name_to_delete))
            except Exception as e:
                conn.rollback()
                flash(("Error Deleting Packaging Material: " + str(e) + "Contact IT Database Error For Restoring Packaging Materials in table PACKAGINGMATERIALS Table & its Dependencies", "error"))
                audit_trail_change(session.get('username'), "Delete PM", "Error Deleting Packaging Material: " + str(e) + "Contact IT Database Error For Restoring Packaging Materials in table PACKAGINGMATERIALS Table & its Dependencies")
            finally:
                cursor.close()

        return render_template('delete_existing_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in

# Endpoint for the "Delete Existing Entry" button
@app.route('/restore_existing_pm', methods=['GET', 'POST'])
def restore_existing_packaging_material_entry():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('restore_existing_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=inversesdropDown('PACKAGINGMATERIALS', 'NAME'))
        
        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function
        if user_privilege not in ['Admin', 'Manager']:
            flash(("You As A {} Do Not Have The Required Privileges To Perform This Action Ask A Manager.".format(user_privilege), "info"))
            return render_template('restore_existing_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=inversesdropDown('PACKAGINGMATERIALS', 'NAME'))
        
        if request.method == 'POST':
            # Get the material name to be deleted from the form
            material_name_to_restore = request.form['material_name']

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            try:
                # Check if the material exists
                cursor.execute("SELECT * FROM PACKAGINGMATERIALS WHERE NAME = ?  AND REMOVED = 'T'", (material_name_to_restore,))
                existing_material = cursor.fetchone()

                if not existing_material:
                    flash(("Material Not Found", "info"))
                else:
                    # Implement code to restore the material (soft restore)
                    cursor.execute("UPDATE PACKAGINGMATERIALS SET REMOVED = 'F' WHERE NAME = ?", (material_name_to_restore,))
                    conn.commit()

                    if cursor.rowcount > 0:
                        flash(("Packaging Material Restored Successfully", "success"))
                        audit_trail_change(session.get('username'), "Restore PM", "Packaging Material Restored Successfully")
                    else:
                        flash(("Packaging Material Not Restored. Please Check The Input.", "info"))
                        audit_trail_change(session.get('username'), "Resotre PM", "Packaging Material Not Restored")

            except Exception as e:
                conn.rollback()
                flash(("Error Restoring Packaging Material: " + str(e) + "Contact IT Database Error for Restoring Packaging Materials in Table PACKAGINGMATERIALS Table & its Dependencies", "error"))
                audit_trail_change(session.get('username'), "Resotre PM", "Error Restoring Packaging Material: " + str(e) + "Contact IT Database Error for Restoring Packaging Materials in Table PACKAGINGMATERIALS Table & its Dependencies")
            finally:
                cursor.close()

        return render_template('restore_existing_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=inversesdropDown('PACKAGINGMATERIALS', 'NAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in


# Endpoint for the "Update Associations" button
@app.route('/update_associations_pm', methods=['GET', 'POST'])
def update_associations_packaging_material():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('update_associations_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))
        
        if request.method == 'POST':
            material_name = request.form['material_name']
            operation = request.form['operation']  # Add or Delete
            associated_codes = request.form.get('associated_codes', '')  # Optional field, default to an empty string

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            try:
                # Check if the material exists
                cursor.execute("SELECT MATERIALID, ASSOCIATED_CODES FROM PACKAGINGMATERIALS WHERE NAME = ? AND REMOVED = 'F'", (material_name,))
                packaging_material_data = cursor.fetchone()

                if not packaging_material_data:
                    flash(("Material Not Found", "info"))
                else:
                    packaging_material_id = packaging_material_data[0]
                    current_associated_codes = packaging_material_data[1]

                    # Initialize current_associated_codes_list before the loop
                    current_associated_codes_list = current_associated_codes.split(', ')

                    if operation == 'Add':
                        if associated_codes:
                            # Split the associated codes into a list and remove leading/trailing spaces
                            associated_codes_list = [code.strip() for code in associated_codes.split(',')]

                            # Check for duplicates in associated codes
                            if len(associated_codes_list) != len(set(associated_codes_list)):
                                flash(("Duplicate Associated Codes Found", "info"))
                            else:
                                # Initialize a list to keep track of new associations
                                new_associated_codes_list = current_associated_codes_list.copy()
                                
                                # Insert new associations and update the new_associated_codes_list
                                for code in associated_codes_list:
                                    # Check if the product code exists
                                    cursor.execute("SELECT * FROM FINISHEDPRODUCT WHERE CODE = ? AND REMOVED = 'F'", (code,))
                                    check_exist_code = cursor.fetchone()

                                    if not check_exist_code:
                                        flash(("Product Code {} Does Not Exist".format(code), "info"))
                                        return render_template('update_associations_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))

                                    # Check if the association already exists
                                    cursor.execute("SELECT * FROM PACKAGINGMATERIALASSOCIATION WHERE PACKAGINGMATERIALID = ? AND CODE = ?", (packaging_material_id, code))
                                    check_association = cursor.fetchone()

                                    if check_association:
                                        flash(("Association for Product Code {} Already Exists".format(code), "info"))
                                        return render_template('update_associations_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))

                                    # Insert the new association
                                    cursor.execute("INSERT INTO PACKAGINGMATERIALASSOCIATION (PACKAGINGMATERIALID, CODE) VALUES (?, ?)", (packaging_material_id, code))
                                    conn.commit()

                                    # Update the new_associated_codes_list
                                    if code not in new_associated_codes_list:
                                        new_associated_codes_list.append(code)

                                # Join the updated new_associated_codes_list and update the associated_codes column
                                if new_associated_codes_list:  # Check if the list is not empty and not None
                                    new_associated_codes_str = ', '.join(new_associated_codes_list)
                                else:
                                    new_associated_codes_str = ''  # Set it to an empty string if the list is empty or None


                                cursor.execute("UPDATE PACKAGINGMATERIALS SET ASSOCIATED_CODES = ? WHERE MATERIALID = ?", (new_associated_codes_str, packaging_material_id))
                                conn.commit()

                                flash(("Associations Added Successfully", "success"))
                                audit_trail_change(session.get('username'), "Update Associations PM", "Packaging Material {} Updated with {}".format(material_name, new_associated_codes_str))

                        else:
                            flash(("No Associations Provided", "info"))

                    elif operation == 'Delete':
                        if associated_codes:
                            # Split the associated codes into a list and remove leading/trailing spaces
                            associated_codes_list = [code.strip() for code in associated_codes.split(',')]

                            # Check if the associations to be deleted exist
                            for code in associated_codes_list:
                                # Check if the association exists
                                cursor.execute("SELECT * FROM PACKAGINGMATERIALASSOCIATION WHERE PACKAGINGMATERIALID = ? AND CODE = ?",
                                            (packaging_material_id, code))
                                check_association = cursor.fetchone()

                                if not check_association:
                                    flash(("Association for Product Code {} Does Not Exist".format(code), "info"))
                                    return render_template('update_associations_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))

                            # Delete the specified associations
                            for code in associated_codes_list:
                                cursor.execute("DELETE FROM PACKAGINGMATERIALASSOCIATION WHERE PACKAGINGMATERIALID = ? AND CODE = ?",
                                            (packaging_material_id, code))
                                conn.commit()

                            # Update the associated_codes column in PACKAGINGMATERIALS
                            current_associated_codes_list = [c for c in current_associated_codes_list if c not in associated_codes_list]
                            updated_associated_codes_str = ', '.join(current_associated_codes_list)
                            cursor.execute("UPDATE PACKAGINGMATERIALS SET ASSOCIATED_CODES = ? WHERE MATERIALID = ?",
                                        (updated_associated_codes_str, packaging_material_id))
                            conn.commit()

                            flash(("Associations Deleted Successfully", "success"))
                            audit_trail_change(session.get('username'), "Update Associations PM", "Packaging Material {} Removed {}".format(material_name, new_associated_codes_str))

                        else:
                            flash(("No Associations Provided for Deletion", "info"))


            except Exception as e:
                conn.rollback()
                flash(("Error Updating Associations: " + str(e), "error"))
            finally:
                cursor.close()

        return render_template('update_associations_pm.html', headers=getheader('PACKAGINGMATERIALS'), data=getdata('PACKAGINGMATERIALS'), material_names=sdropDown('PACKAGINGMATERIALS', 'NAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in
    

'''
    Finished Product Functions. All of the flask endpoints below are specific to Finished Products.
'''

@app.route('/finished_products', methods=['GET', 'POST'])
def finished_products():

    '''
        finished_products function handles the /finished_products route.
    '''
    
    if 'username' in session:
        return render_template('finished_products.html')
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in
    

# Endpoint for the "Receive" button
@app.route('/receive_fp', methods=['GET', 'POST'])
def receive_finished_product():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('receive_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=sdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))
        
        if request.method == 'POST':
            product_name = request.form['product_name']
            quantity_received = request.form['quantity_received']

            # Check if the quantity received is a positive integer
            try:
                quantity_received = int(quantity_received)
                if quantity_received <= 0:
                    flash(("Quantity must be a positive integer.", "info"))
                    return render_template('receive_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=sdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))
            except ValueError:
                flash(("Quantity must be a positive integer.", "info"))
                return render_template('receive_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=sdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            # Check if the raw material exists
            cursor.execute("SELECT * FROM FINISHEDPRODUCT WHERE PRODUCTNAME = ? AND REMOVED = 'F'", (product_name,))
            raw_material = cursor.fetchone()

            if not raw_material:
                flash(("Finished Product Does Not Exist.", "info"))
            else:
                try:
                    # Update the quantity of the raw material in the database
                    new_quantity = raw_material[4] + quantity_received
                    # print(new_quantity)
                    cursor.execute("UPDATE FINISHEDPRODUCT SET QUANTITY = ? WHERE PRODUCTNAME = ? AND REMOVED = 'F'", (new_quantity, product_name))
                    conn.commit()

                    flash(("Successfully Received {} Units of {} Into Inventory.".format(quantity_received, product_name), "success"))
                    audit_trail_change(session.get('username'), "Recieve FP", "Successfully Received {} Units of {} Into Inventory.".format(quantity_received, product_name))
                except Exception as e:
                    conn.rollback()
                    flash(("Error Receiving Finished Products: {}. Contact IT For Assistance With Finished Products.".format(str(e)), "error"))
                    audit_trail_change(session.get('username'), "Recieve FP", "Error Receiving Finished Products: {}. Contact IT For Assistance With Finished Products.".format(str(e)))
                finally:
                    cursor.close()

        return render_template('receive_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=sdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in

# Endpoint for the "Use" button
@app.route('/use_fp', methods=['GET', 'POST'])
def use_finished_product():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('use_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=sdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))
        
        if request.method == 'POST':
            product_name = request.form['product_name']
            quantity_used = request.form['quantity_used']

            # Check if the quantity used is a positive integer
            try:
                quantity_used = int(quantity_used)
                if quantity_used <= 0:
                    flash(("Quantity must be a positive integer.", "info"))
                    return render_template('use_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=sdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))
            except ValueError:
                flash(("Quantity must be a positive integer.", "info"))
                return render_template('use_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=sdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            # Check if the Finished Product exists
            cursor.execute("SELECT * FROM FINISHEDPRODUCT WHERE PRODUCTNAME = ? AND REMOVED = 'F'", (product_name,))
            raw_material = cursor.fetchone()

            if not raw_material:
                flash(("Material Does Not Exist.", "info"))
            else:
                try:
                    current_quantity = raw_material[4]
                    
                    # Check if there is enough quantity to use
                    if current_quantity >= quantity_used:
                        new_quantity = current_quantity - quantity_used
                        cursor.execute("UPDATE FINISHEDPRODUCT SET QUANTITY = ? WHERE PRODUCTNAME = ? AND REMOVED = 'F'", (new_quantity, product_name))
                        conn.commit()

                        flash(("Successfully Used {} Units of {}.".format(quantity_used, product_name), "success"))
                        audit_trail_change(session.get('username'), "Use FP", "Successfully Used {} Units of {}.".format(quantity_used, product_name))
                    else:
                        flash(("Insufficient quantity of {} available.".format(product_name), "info"))
                        audit_trail_change(session.get('username'), "Use FP", "Insufficient quantity of {} available.".format(product_name))

                except Exception as e:
                    conn.rollback()
                    flash(("Error Using Finished Product: {}. Contact IT For Assistance With Finished Products.".format(str(e)), "error"))
                finally:
                    cursor.close()

        return render_template('use_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=sdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in


# Endpoint for the "Adjust" button
@app.route('/adjust_fp', methods=['GET', 'POST'])
def adjust_finished_product():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('adjust_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=sdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))
        
        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function
        if user_privilege not in ['Admin', 'Manager']:
            flash(("You As A {} Do Not Have The Required Privileges To Perform This Action Ask A Manager.".format(user_privilege), "info"))
            return render_template('adjust_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=sdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))
        
        if request.method == 'POST':
            product_name = request.form['product_name']
            new_quantity = request.form['new_quantity']

            # Check if the new quantity is a positive integer
            try:
                new_quantity = int(new_quantity)
                if new_quantity < 0:
                    flash(("New quantity cannot be negative.", "info"))
                    return render_template('adjust_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=sdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))
            except ValueError:
                flash(("New quantity must be a positive integer.", "info"))
                return render_template('adjust_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=sdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            # Check if the finished product exists
            cursor.execute("SELECT * FROM FINISHEDPRODUCT WHERE PRODUCTNAME = ? AND REMOVED = 'F'", (product_name,))
            finished_product = cursor.fetchone()

            if not finished_product:
                flash(("Finished Product Does Not Exist.", "info"))
            else:
                try:
                    cursor.execute("UPDATE FINISHEDPRODUCT SET QUANTITY = ? WHERE PRODUCTNAME = ? AND REMOVED = 'F'", (new_quantity, product_name))
                    conn.commit()

                    flash(("Successfully Adjusted Quantity of {} to {}.".format(product_name, new_quantity), "success"))
                    audit_trail_change(session.get('username'), "Adjust FP", "Successfully Adjusted Quantity of {} to {}.".format(product_name, new_quantity))
                except Exception as e:
                    conn.rollback()
                    flash(("Error Adjusting Finished Product Quantity: {}. Contact IT For Assistance With Finished Products.".format(str(e)), "error"))
                    audit_trail_change(session.get('username'), "Adjust FP", "Error Adjusting Finished Product Quantity: {}. Contact IT For Assistance With Finished Products.".format(str(e)))
                finally:
                    cursor.close()

        return render_template('adjust_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=sdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in
    

# Endpoint for adding a new finished product
@app.route('/add_new_fp', methods=['GET', 'POST'])
def add_new_fp():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('add_new_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), units=sdropDown('UNITS_FP', 'NAME'))
        
        if request.method == 'POST':
            product_code = request.form['product_code']
            product_name = request.form['product_name']
            cost = float(request.form['cost'])
            unit = request.form['units']
            quantity = int(request.form['quantity'])
            price = float(request.form['price'])

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            if quantity < 0 or cost < 0 or price < 0:
                flash(("Do Not Insert Negative Values", "info"))
                return render_template('add_new_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), units=sdropDown('UNITS_FP', 'NAME'))

            try:
                # Check if the product code already exists
                cursor.execute("SELECT * FROM FINISHEDPRODUCT WHERE CODE = ?", (product_code,))
                check_exist_code = cursor.fetchone()

                if check_exist_code:
                    flash(("Product Code '{}' Already Exists".format(product_code), "info"))
                    return render_template('add_new_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), units=sdropDown('UNITS_FP', 'NAME'))
                
                # Check if the product code already exists
                cursor.execute("SELECT * FROM FINISHEDPRODUCT WHERE PRODUCTNAME = ?", (product_name,))
                check_exist_code = cursor.fetchone()

                if check_exist_code:
                    flash(("Product Name '{}' Already Exists".format(product_name), "info"))
                    return render_template('add_new_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), units=sdropDown('UNITS_FP', 'NAME'))

                # Insert the new finished product
                cursor.execute("INSERT INTO FINISHEDPRODUCT (CODE, PRODUCTNAME, COST, UNIT, QUANTITY, PRICE, REMOVED) VALUES (?, ?, ?, ?, ?, ?, ?)",
                               (product_code, product_name, cost, unit, quantity, price, 'F'))
                conn.commit()

                flash(("Finished Product Added Successfully", "success"))
                audit_trail_change(session.get('username'), "Add New FP", "Finished Product {} Added Successfully".format(product_name))
            except Exception as e:
                conn.rollback()
                flash(("Error Adding Finished Product: " + str(e) + "Error Raised Could be Database Related.", "error"))
            finally:
                cursor.close()

        return render_template('add_new_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), units=sdropDown('UNITS_FP', 'NAME'))
    else:
        return redirect(url_for('login'))  # Redirect to the login page if not logged in


# Endpoint for the "Delete Existing Entry" button
@app.route('/delete_existing_fp', methods=['GET', 'POST'])
def delete_existing_finished_product_entry():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('delete_existing_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=sdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function
        if user_privilege not in ['Admin', 'Manager']:
            flash(("You As A {} Do Not Have The Required Privileges To Perform This Action Ask A Manager.".format(user_privilege), "info"))
            return render_template('delete_existing_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=sdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))

        if request.method == 'POST':
            # Get the product name to be deleted from the form
            product_name_to_delete = request.form['product_name']

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            try:
                # Check if the product name exists
                cursor.execute("SELECT * FROM FINISHEDPRODUCT WHERE PRODUCTNAME = ? AND REMOVED = 'F'", (product_name_to_delete,))
                existing_product = cursor.fetchone()

                if not existing_product:
                    flash(("Product Not Found", "info"))
                else:
                    # Implement code to delete the material (soft delete)
                    cursor.execute("UPDATE FINISHEDPRODUCT SET REMOVED = 'T' WHERE PRODUCTNAME = ?", (product_name_to_delete,))
                    conn.commit()

                    if cursor.rowcount > 0:
                        flash(("Finished Product Deleted Successfully", "success"))
                        audit_trail_change(session.get('username'), "Delete FP", "Finished Product {} Deleted Successfully".format(product_name_to_delete))
                    else:
                        flash(("Finished Product Not Deleted. Please Check The Input.", "info"))
                        audit_trail_change(session.get('username'), "Delete FP", "Finished Product {} Deleted Successfully".format(product_name_to_delete))

            except Exception as e:
                conn.rollback()
                flash(("Error Deleting Finished Product : " + str(e) + "Contact IT Database Error For Deleting Finished Product in table FINISHEDPRODUCT Table & its Dependencies", "error"))
            finally:
                cursor.close()

        return render_template('delete_existing_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=sdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in

# Endpoint for the "Delete Existing Entry" button
@app.route('/restore_existing_fp', methods=['GET', 'POST'])
def restore_existing_finished_product():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('restore_existing_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=inversesdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))
        

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function
        if user_privilege not in ['Admin', 'Manager']:
            flash(("You As A {} Do Not Have The Required Privileges To Perform This Action Ask A Manager.".format(user_privilege), "info"))
            return render_template('restore_existing_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=inversesdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))
        
        if request.method == 'POST':
            # Get the product name to be restored from the form
            product_name_to_restore = request.form['product_name']

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            try:
                # Check if the material exists
                cursor.execute("SELECT * FROM FINISHEDPRODUCT WHERE PRODUCTNAME = ?  AND REMOVED = 'T'", (product_name_to_restore,))
                existing_material = cursor.fetchone()

                if not existing_material:
                    flash(("Material Not Found", "info"))
                else:
                    # Implement code to restore the material (soft restore)
                    cursor.execute("UPDATE FINISHEDPRODUCT SET REMOVED = 'F' WHERE PRODUCTNAME = ?", (product_name_to_restore,))
                    conn.commit()

                    if cursor.rowcount > 0:
                        flash(("Finished Product Restored Successfully", "success"))
                        audit_trail_change(session.get('username'), "Restored FP", "Finished Product {} Restored Successfully".format(product_name_to_restore))
                    else:
                        flash(("Finished Product Not Restored. Please Check The Input.", "info"))
                        audit_trail_change(session.get('username'), "Restored FP", "Finished Product {} Restored Successfully".format(product_name_to_restore))

            except Exception as e:
                conn.rollback()
                flash(("Error Restoring Finished Product: " + str(e) + "Contact IT database error for restoring Finished Product  in table FINISHEDPRODUCT Table & its Dependencies", "error"))
            finally:
                cursor.close()

        return render_template('restore_existing_fp.html', headers=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), product_names=inversesdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in
    
# Endpoint for the "Update Associations For FInished Products" page

# Endpoint for updating associations for finished products
@app.route('/update_associations_fp', methods=['GET', 'POST'])
def update_associations_fp():
    if 'username' in session:
        # Check user privileges
        user_privilege = get_user_privilege(session['username'])
        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program.", "info"))
            return render_template('update_associations_fp.html', header=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), productName=sdropDown('FINISHEDPRODUCT', 'CODE'))

        if request.method == 'POST':
            operation = request.form.get('operation')  # Add or Delete
            material_type = request.form.get('material_type')  # Raw or Packaging
            product_code = request.form.get('product_code')
            associated_ID = request.form.get('associated_ID', '')  # Optional field, default to an empty string

            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            try:
                # Check if the product code exists
                cursor.execute("SELECT * FROM FINISHEDPRODUCT WHERE CODE = ? AND REMOVED = 'F'", (product_code,))
                product_data = cursor.fetchone()

                if not product_data:
                    flash(("Product Code Not Found or Already Removed", "info"))
                else:
                    if material_type == 'Raw':
                        # Handle associations with raw materials
                        handle_raw_material_associations(cursor, operation, product_code, associated_ID)
                    elif material_type == 'Packaging':
                        # Handle associations with packaging materials
                        handle_packaging_material_associations(cursor, operation, product_code, associated_ID)
                    else:
                        flash(("Invalid Material Type", "info"))

            except Exception as e:
                conn.rollback()
                flash(("Error Updating Associations: " + str(e), "error"))
            finally:
                cursor.close()

        return render_template('update_associations_fp.html', header=getheader('FINISHEDPRODUCT'), data=getdata('FINISHEDPRODUCT'), units=sdropDown('FINISHEDPRODUCT', 'PRODUCTNAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in

# Function to handle associations with raw materials
# Function to handle associations with raw materials
def handle_raw_material_associations(cursor, operation, product_code, associated_material_ids):
    try:
        # Split the associated material IDs into a list
        associated_ids_list = [int(id.strip()) for id in associated_material_ids.split(',')]

        # Check for duplicates in associated IDs
        if len(associated_ids_list) != len(set(associated_ids_list)):
            flash(("Duplicate Associated Material IDs Found", "info"))
            return

        # Initialize a list to keep track of new associations
        new_associated_ids_list = []

        for material_id in associated_ids_list:
            # Check if the raw material ID exists and is not removed
            cursor.execute("SELECT MATERIALID FROM RAWMATERIALS WHERE MATERIALID = ? AND REMOVED = 'F'", (material_id,))
            raw_material_data = cursor.fetchone()

            if not raw_material_data:
                flash(("Raw Material with ID '{}' Not Found or Already Removed".format(material_id), "info"))
                return

            if operation == 'Add':
                # Check if the association already exists
                cursor.execute("SELECT * FROM RAWMATERIALASSOCIATION WHERE RAWMATERIALID = ? AND CODE = ?", (material_id, product_code))
                check_association = cursor.fetchone()

                if check_association:
                    flash(("Association for Product Code {} Already Exists with Raw Material ID '{}'".format(product_code, material_id), "info"))
                    return

                # Insert the new association
                cursor.execute("INSERT INTO RAWMATERIALASSOCIATION (RAWMATERIALID, CODE) VALUES (?, ?)", (material_id, product_code))
                conn.commit()

                # Get the current associated codes and add the new product code
                cursor.execute("SELECT ASSOCIATED_CODES FROM RAWMATERIALS WHERE MATERIALID = ?", (material_id,))
                current_associations = cursor.fetchone()[0]

                if current_associations:
                    current_associations_list = [code.strip() for code in current_associations.split(',')]
                    if product_code not in current_associations_list:
                        current_associations_list.append(product_code)
                        updated_associations = ', '.join(current_associations_list)
                    else:
                        flash(("Association for Product Code {} Already Exists with Raw Material ID '{}'".format(product_code, material_id), "info"))
                        return
                else:
                    updated_associations = product_code

                # Update the ASSOCIATED_CODES column with the updated list
                cursor.execute("UPDATE RAWMATERIALS SET ASSOCIATED_CODES = ? WHERE MATERIALID = ?", (updated_associations, material_id))
                conn.commit()

                # Update the new_associated_ids_list
                new_associated_ids_list.append(material_id)
            elif operation == 'Delete':
                # Check if the association exists
                cursor.execute("SELECT * FROM RAWMATERIALASSOCIATION WHERE RAWMATERIALID = ? AND CODE = ?", (material_id, product_code))
                check_association = cursor.fetchone()

                if not check_association:
                    flash(("Association for Product Code {} Does Not Exist with Raw Material ID '{}'".format(product_code, material_id), "info"))
                    return

                # Delete the association
                cursor.execute("DELETE FROM RAWMATERIALASSOCIATION WHERE RAWMATERIALID = ? AND CODE = ?", (material_id, product_code))
                conn.commit()

                # Get the current associated codes and remove the product code
                cursor.execute("SELECT ASSOCIATED_CODES FROM RAWMATERIALS WHERE MATERIALID = ?", (material_id,))
                current_associations = cursor.fetchone()[0]

                if current_associations:
                    current_associations_list = [code.strip() for code in current_associations.split(',')]
                    if product_code in current_associations_list:
                        current_associations_list.remove(product_code)
                        updated_associations = ', '.join(current_associations_list)
                    else:
                        flash(("Association for Product Code {} Does Not Exist with Raw Material ID '{}'".format(product_code, material_id), "info"))
                        return
                else:
                    flash(("No Associations Found for Raw Material ID '{}'".format(material_id), "info"))
                    return

                # Update the ASSOCIATED_CODES column with the updated list
                cursor.execute("UPDATE RAWMATERIALS SET ASSOCIATED_CODES = ? WHERE MATERIALID = ?", (updated_associations, material_id))
                conn.commit()

        if operation == 'Add':
            flash(("Associations with Raw Materials Added Successfully", "success"))
            audit_trail_change(session.get('username'), "Update Associations FP", "Finished Product {} Associated To: {}".format(product_code, updated_associations))
        elif operation == 'Delete':
            flash(("Associations with Raw Materials Deleted Successfully", "success"))
            audit_trail_change(session.get('username'), "Update Associations FP", "Finished Product {} Removed Association To: {}".format(product_code, updated_associations))

    except Exception as e:
        conn.rollback()
        flash(("Error Updating Associations with Raw Materials: " + str(e), "error"))



# Function to handle associations with packaging materials
def handle_packaging_material_associations(cursor, operation, product_code, associated_material_ids):
    try:
        # Split the associated material IDs into a list
        associated_ids_list = [int(id.strip()) for id in associated_material_ids.split(',')]

        # Check for duplicates in associated IDs
        if len(associated_ids_list) != len(set(associated_ids_list)):
            flash(("Duplicate Associated Material IDs Found", "info"))
            return

        for material_id in associated_ids_list:
            # Check if the packaging material ID exists and is not removed
            cursor.execute("SELECT MATERIALID FROM PACKAGINGMATERIALS WHERE MATERIALID = ? AND REMOVED = 'F'", (material_id,))
            packaging_material_data = cursor.fetchone()

            if not packaging_material_data:
                flash(("Packaging Material with ID '{}' Not Found or Already Removed".format(material_id), "info"))
                return

            if operation == 'Add':
                # Check if the association already exists
                cursor.execute("SELECT * FROM PACKAGINGMATERIALASSOCIATION WHERE PACKAGINGMATERIALID = ? AND CODE = ?", (material_id, product_code))
                check_association = cursor.fetchone()

                if check_association:
                    flash(("Association for Product Code {} Already Exists with Packaging Material ID '{}'".format(product_code, material_id), "info"))
                    return

                # Insert the new association
                cursor.execute("INSERT INTO PACKAGINGMATERIALASSOCIATION (PACKAGINGMATERIALID, CODE) VALUES (?, ?)", (material_id, product_code))
                conn.commit()

                # Get the current associated codes and add the new product code
                cursor.execute("SELECT ASSOCIATED_CODES FROM PACKAGINGMATERIALS WHERE MATERIALID = ?", (material_id,))
                current_associations = cursor.fetchone()[0]

                if current_associations:
                    current_associations_list = [code.strip() for code in current_associations.split(',')]
                    if product_code not in current_associations_list:
                        current_associations_list.append(product_code)
                        updated_associations = ', '.join(current_associations_list)
                    else:
                        flash(("Association for Product Code {} Already Exists with Packaging Material ID '{}'".format(product_code, material_id), "info"))
                        return
                else:
                    updated_associations = product_code

                # Update the ASSOCIATED_CODES column with the updated list
                cursor.execute("UPDATE PACKAGINGMATERIALS SET ASSOCIATED_CODES = ? WHERE MATERIALID = ?", (updated_associations, material_id))
                conn.commit()

            elif operation == 'Delete':
                # Check if the association exists
                cursor.execute("SELECT * FROM PACKAGINGMATERIALASSOCIATION WHERE PACKAGINGMATERIALID = ? AND CODE = ?", (material_id, product_code))
                check_association = cursor.fetchone()

                if not check_association:
                    flash(("Association for Product Code {} Does Not Exist with Packaging Material ID '{}'".format(product_code, material_id), "info"))
                    return

                # Delete the association
                cursor.execute("DELETE FROM PACKAGINGMATERIALASSOCIATION WHERE PACKAGINGMATERIALID = ? AND CODE = ?", (material_id, product_code))
                conn.commit()

                # Get the current associated codes and remove the product code
                cursor.execute("SELECT ASSOCIATED_CODES FROM PACKAGINGMATERIALS WHERE MATERIALID = ?", (material_id,))
                current_associations = cursor.fetchone()[0]

                if current_associations:
                    current_associations_list = [code.strip() for code in current_associations.split(',')]
                    if product_code in current_associations_list:
                        current_associations_list.remove(product_code)
                        updated_associations = ', '.join(current_associations_list)
                    else:
                        flash(("Association for Product Code {} Does Not Exist with Packaging Material ID '{}'".format(product_code, material_id), "info"))
                        return
                else:
                    flash(("No Associations Found for Packaging Material ID '{}'".format(material_id), "info"))
                    return

                # Update the ASSOCIATED_CODES column with the updated list
                cursor.execute("UPDATE PACKAGINGMATERIALS SET ASSOCIATED_CODES = ? WHERE MATERIALID = ?", (updated_associations, material_id))
                conn.commit()

        if operation == 'Add':
            flash(("Associations with Packaging Materials Added Successfully", "success"))
            audit_trail_change(session.get('username'), "Update Associations FP", "Finished Product {} Associated To: {}".format(product_code, updated_associations))
        elif operation == 'Delete':
            flash(("Associations with Packaging Materials Deleted Successfully", "success"))
            audit_trail_change(session.get('username'), "Update Associations FP", "Finished Product {} Removed Association To: {}".format(product_code, updated_associations))

    except Exception as e:
        conn.rollback()
        flash(("Error Updating Associations with Packaging Materials: " + str(e), "error"))


# Endpoint for the "Manage Units" page

@app.route('/manage_units_fp', methods=['GET', 'POST'])
def manage_units_fp():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('manage_units_fp.html', header=getheader('UNITS_FP'), data=getdata('UNITS_FP'), units=sdropDown('UNITS_FP', 'NAME'))
        
        if request.method == 'POST':
            unit_name = request.form['unit_name']
            action = request.form['action']
            
            # Create a cursor object within the local scope of this if block
            cursor = conn.cursor()

            # Perform the action (add, delete, or restore) based on the user's choice
            if action == 'add':
                try:

                    cursor.execute("SELECT * FROM UNITS_FP WHERE NAME = ?", (unit_name,))
                    checkUnit = cursor.fetchone()

                    if (checkUnit):
                        flash(("Unit '{}' Already Exists (Check Removed & Existing Units)".format(unit_name), "info"))
                        return render_template('manage_units_fp.html', header=getheader('UNITS_FP'), data=getdata('UNITS_FP'), units=sdropDown('UNITS_FP', 'NAME'))
                                    
                    # Implement code to add the unit to the database
                    cursor.execute("INSERT INTO UNITS_FP (NAME, REMOVED) VALUES (?, ?)", (unit_name, 'F'))
                    conn.commit()
                    if cursor.rowcount > 0:
                        flash(("Unit '{}' Added Successfully".format(unit_name), "success"))
                        audit_trail_change(session.get('username'), "Manage Units FP", "Unit '{}' Added Successfully".format(unit_name))
                    else:
                        flash(("Unit '{}' Not Added. Please Check The Input.".format(unit_name), "info"))
                except Exception as e:
                    conn.rollback()
                    flash(("Error Adding Unit: " + str(e) + " Contact IT Database Error For Adding Units in Table UNITS_FP", "error"))
                finally:
                    cursor.close()
            elif action == 'delete':
                try:                    
                    # Implement code to delete the unit from the database (soft delete)
                    cursor.execute("UPDATE UNITS_FP SET REMOVED = 'T' WHERE NAME = ? AND REMOVED = 'F'", (unit_name,))
                    conn.commit()
                    if cursor.rowcount > 0:
                        flash(("Unit '{}' Deleted Successfully".format(unit_name), "success"))
                        audit_trail_change(session.get('username'), "Manage Units FP", "Unit '{}' Deleted Successfully".format(unit_name))
                    else:
                        flash(("Unit '{}' Not Found or Not Deleted. Please Check The Input.".format(unit_name), "info"))
                except Exception as e:
                    conn.rollback()
                    flash(("Error Deleting Unit: " + str(e) + " Contact IT Database Error For Adding Units in Table UNITS_FP", "error"))
                finally:
                    cursor.close()
            elif action == 'restore':
                try:
                    # Implement code to restore the unit in the database
                    cursor.execute("UPDATE UNITS_FP SET REMOVED = 'F' WHERE NAME = ? AND REMOVED = 'T'", (unit_name,))
                    conn.commit()
                    if cursor.rowcount > 0:
                        flash(("Unit '{}' Restored Successfully".format(unit_name), "success"))
                        audit_trail_change(session.get('username'), "Manage Units FP", "Unit '{}' Restored Successfully".format(unit_name))
                    else:
                        flash(("Unit '{}' Not Found or Not Restored. Please Check The Input.".format(unit_name), "info"))
                except Exception as e:
                    conn.rollback()
                    flash(("Error Restoring Unit: " + str(e) + "Contact IT database error for restoring units in table UNITS_FP", "error"))
                finally:
                    cursor.close()

        return render_template('manage_units_fp.html', header=getheader('UNITS_FP'), data=getdata('UNITS_FP'), units=sdropDown('UNITS_FP', 'NAME'))
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in


'''

    Below is code endpoints for all things related work order

'''

@app.route('/work_order')
def work_order():
    '''
    index function contains the logic to render the user_options.
    '''
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Do Not Have Any Access To This Page. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('work_order.html')
        
        return render_template('work_order.html')
    else:
        return redirect(url_for('login'))  # Redirect to the login page if not logged in


# @app.route('/create_work_order', methods=['GET', 'POST'])             ITERATION 1
# def create_work_order():
#     if 'username' in session:

#         # Check if the user has the required privileges (Admin or Manager)
#         user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

#         if user_privilege == 'Read-Only-User':
#             flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).", "info"))
#             return render_template('manage_units_fp.html', header=getheader('UNITS_FP'), data=getdata('UNITS_FP'), units=sdropDown('UNITS_FP', 'NAME'))
        
#         if request.method == 'POST':
#             # Retrieve contact name and product/quantity data from the form
#             contact_name = request.form['contact_name']
#             due_by = request.form['due_by']
#             product_quantity_data = []

#             cursor = conn.cursor()
#             cursor.execute("SELECT COUNT(*) FROM FINISHEDPRODUCT WHERE REMOVED = 'F'")
#             product_count = cursor.fetchone()[0]  # Fetch the count as an integer

#             # Retrieve the entry count from the form
#             entry_count = int(request.form.get('entry_count', 0))

#             # Check if the number of entries exceeds the maximum
#             if entry_count > product_count:
#                 flash(("Cannot Exceeded The Maximum Number of Product Entries {}.".format(product_count), "info"))
#                 return render_template('create_work_order.html', contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'), codes=sdropDown('FINISHEDPRODUCT', 'CODE'))

#             # Keep track of used product codes
#             used_product_codes = set()

#             # Iterate through the submitted form data to extract product code and quantity pairs
#             for i in range(1, product_count + 1):  # Adjust the range as needed
#                 product_code = request.form.get(f'product_code_{i}')
#                 quantity = request.form.get(f'quantity_{i}')

#                 if product_code and quantity:
#                     # Check if the product code is unique
#                     if product_code not in used_product_codes:
#                         used_product_codes.add(product_code)
#                         product_quantity_data.append([product_code, quantity])
#                     else:
#                         # Handle the case where a duplicate product code is entered
#                         flash(("Duplicate product code found: {}.".format(product_code), "info"))
#                         return render_template('create_work_order.html', contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'), codes=sdropDown('FINISHEDPRODUCT', 'CODE'))

#                     # Check if the product code exists in the database
#                     cursor.execute("SELECT COUNT(*) FROM FINISHEDPRODUCT WHERE CODE = ? AND REMOVED = 'F'", (product_code,))
#                     code_exists = cursor.fetchone()[0]

#                     if code_exists == 0:
#                         flash(("A Product code given does not exist: '{}'.".format(product_code), "info"))
#                         return render_template('create_work_order.html', contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'), codes=sdropDown('FINISHEDPRODUCT', 'CODE'))

#             # Check if the customer exists in the database
#             cursor.execute("SELECT COUNT(*) FROM CUSTOMERS WHERE CONTACT_NAME = ? AND REMOVED = 'F'", (contact_name,))
#             customer_count = cursor.fetchone()[0]

#             if customer_count == 0:
#                 flash(("Customer '{}' does not exist.".format(contact_name), "info"))
#                 return render_template('create_work_order.html', contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'), codes=sdropDown('FINISHEDPRODUCT', 'CODE'))

#             created_on = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
#             print(contact_name, created_on, due_by)
#             cursor.execute("INSERT INTO WORK_ORDERS_INFO (CONTACT_NAME, CREATED_ON, DUE_BY, STATUS) VALUES (?, ?, ?, ?)",
#                (contact_name, created_on, due_by, 'In-Progress'))
#             conn.commit()

#             print(check_product_availability(cursor, product_quantity_data))
#             cursor.close()
#             # # Print the data (for testing)
#             # print(f"Contact Name: {contact_name}")
#             # print("Product/Quantity Data:")
#             # for item in product_quantity_data:
#             #     print((f"Product Code: {item[0]}, Quantity: {item[1]}"))

#         return render_template('create_work_order.html', contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'), codes=sdropDown('FINISHEDPRODUCT', 'CODE'))
#     else:
#         return redirect(url_for('login'))

@app.route('/create_work_order', methods=['GET', 'POST'])
def create_work_order():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).", "info"))
            return render_template('work_order.html', header=getheader('UNITS_FP'), data=getdata('UNITS_FP'), units=sdropDown('UNITS_FP', 'NAME'))
        
        if request.method == 'POST':
            # Retrieve contact name and product/quantity data from the form
            contact_name = request.form['contact_name']
            due_by = request.form['due_by']
            product_quantity_data = []

            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM FINISHEDPRODUCT WHERE REMOVED = 'F'")
            product_count = cursor.fetchone()[0]  # Fetch the count as an integer

            # Retrieve the entry count from the form
            entry_count = int(request.form.get('entry_count', 0))

            # Check if the number of entries exceeds the maximum
            if entry_count > product_count:
                flash(("Cannot Exceeded The Maximum Number of Product Entries {}.".format(product_count), "info"))
                return render_template('create_work_order.html', contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'), codes=sdropDown('FINISHEDPRODUCT', 'CODE'))

            # Keep track of used product codes
            used_product_codes = set()

            # Iterate through the submitted form data to extract product code and quantity pairs
            for i in range(1, product_count + 1):  # Adjust the range as needed
                product_code = request.form.get(f'product_code_{i}')
                quantity = request.form.get(f'quantity_{i}')

                if product_code and quantity:
                    # Check if the product code is unique
                    if product_code not in used_product_codes:
                        used_product_codes.add(product_code)
                        product_quantity_data.append([product_code, quantity])
                    else:
                        # Handle the case where a duplicate product code is entered
                        flash(("Duplicate product code found: {}.".format(product_code), "info"))
                        return render_template('create_work_order.html', contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'), codes=sdropDown('FINISHEDPRODUCT', 'CODE'))

                    # Check if the product code exists in the database
                    cursor.execute("SELECT COUNT(*) FROM FINISHEDPRODUCT WHERE CODE = ? AND REMOVED = 'F'", (product_code,))
                    code_exists = cursor.fetchone()[0]

                    if code_exists == 0:
                        flash(("A Product code given does not exist: '{}'.".format(product_code), "info"))
                        return render_template('create_work_order.html', contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'), codes=sdropDown('FINISHEDPRODUCT', 'CODE'))

            # Check if the customer exists in the database
            cursor.execute("SELECT COUNT(*) FROM CUSTOMERS WHERE CONTACT_NAME = ? AND REMOVED = 'F'", (contact_name,))
            customer_count = cursor.fetchone()[0]

            if customer_count == 0:
                flash(("Customer '{}' does not exist.".format(contact_name), "info"))
                return render_template('create_work_order.html', contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'), codes=sdropDown('FINISHEDPRODUCT', 'CODE'))

            created_on = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            cursor.execute("INSERT INTO WORK_ORDERS_INFO (CONTACT_NAME, CREATED_ON, DUE_BY, STATUS) VALUES (?, ?, ?, ?)",
               (contact_name, created_on, due_by, 'In-Progress'))
            conn.commit()
            cursor.close()
            audit_trail_change(session.get('username'), "Created Work Order", "Contact Name '{}' Products: {}".format(contact_name, product_quantity_data))
            # Call check_product_availability to get availability information
            availability_info = check_product_availability(product_quantity_data)
            # cursor.close()

            # Pass availability_info to the template
            return render_template('create_work_order.html',
                                   contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'),
                                   codes=sdropDown('FINISHEDPRODUCT', 'CODE'),
                                   availability_info=availability_info)

        return render_template('create_work_order.html', contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'), codes=sdropDown('FINISHEDPRODUCT', 'CODE'))
    else:
        return redirect(url_for('login'))


def check_product_availability(product_quantity_data):
    cursor = conn.cursor()
    availability_info = {}

    for product_code, quantity_requested in product_quantity_data:
        # Get the current quantity of the finished product
        cursor.execute("SELECT QUANTITY FROM FINISHEDPRODUCT WHERE CODE = ?", (product_code,))
        current_quantity = cursor.fetchone()[0]

        # Convert quantity_requested to an integer
        quantity_requested = int(quantity_requested)

        if current_quantity >= quantity_requested:
            availability_info[product_code] = {
                "available_quantity": current_quantity,
                "status": "Enough Finished Products Available",
                "total_required": quantity_requested,  # Add total required field
            }
        else:
            shortage_quantity = quantity_requested - current_quantity

            # Initialize lists to store missing raw materials and packaging materials
            missing_raw_materials = []
            missing_packaging_materials = []

            # Check for missing raw materials
            cursor.execute(
                "SELECT RAWMATERIALID FROM RAWMATERIALASSOCIATION WHERE CODE = ?",
                (product_code,),
            )
            associated_raw_materials = cursor.fetchall()

            for raw_material in associated_raw_materials:
                raw_material_id = raw_material[0]
                cursor.execute(
                    "SELECT QUANTITY FROM RAWMATERIALS WHERE MATERIALID = ?",
                    (raw_material_id,),
                )
                raw_material_quantity = cursor.fetchone()[0]

                if raw_material_quantity <= 0:
                    missing_raw_materials.append(raw_material_id)

            # Check for missing packaging materials
            cursor.execute(
                "SELECT PACKAGINGMATERIALID FROM PACKAGINGMATERIALASSOCIATION WHERE CODE = ?",
                (product_code,),
            )
            associated_packaging_materials = cursor.fetchall()

            for packaging_material in associated_packaging_materials:
                packaging_material_id = packaging_material[0]
                cursor.execute(
                    "SELECT QUANTITY FROM PACKAGINGMATERIALS WHERE MATERIALID = ?",
                    (packaging_material_id,),
                )
                packaging_material_quantity = cursor.fetchone()[0]

                if packaging_material_quantity <= 0:
                    missing_packaging_materials.append(packaging_material_id)

            if missing_raw_materials or missing_packaging_materials:
                # There are missing raw materials or packaging materials
                availability_info[product_code] = {
                    "available_quantity": current_quantity,
                    "status": f"Cannot Produce - Insufficient Materials. Need {shortage_quantity} More",
                    "missing_raw_materials": missing_raw_materials,
                    "missing_packaging_materials": missing_packaging_materials,
                    "total_required": quantity_requested,  # Add total required field
                }
            else:
                # All required materials are available
                availability_info[product_code] = {
                    "available_quantity": current_quantity,
                    "status": f"Not Enough Finished Products. Can Potentially Produce or Buy {shortage_quantity} More",
                    "total_required": quantity_requested,  # Add total required field
                }

    cursor.close()
    return availability_info


# def check_product_availability(product_quantity_data):
#     cursor = conn.cursor()
#     availability_info = {}

#     for product_code, quantity_requested in product_quantity_data:
#         # Get the current quantity of the finished product
#         cursor.execute("SELECT QUANTITY FROM FINISHEDPRODUCT WHERE CODE = ?", (product_code,))
#         current_quantity = cursor.fetchone()[0]

#         # Convert quantity_requested to an integer
#         quantity_requested = int(quantity_requested)

#         if current_quantity >= quantity_requested:
#             availability_info[product_code] = {
#                 "available_quantity": current_quantity,
#                 "status": "Enough Finished Products Available",
#             }
#         else:
#             shortage_quantity = quantity_requested - current_quantity

#             # Initialize lists to store missing raw materials and packaging materials
#             missing_raw_materials = []
#             missing_packaging_materials = []

#             # Check for missing raw materials
#             cursor.execute(
#                 "SELECT RAWMATERIALID FROM RAWMATERIALASSOCIATION WHERE CODE = ?",
#                 (product_code,),
#             )
#             associated_raw_materials = cursor.fetchall()

#             for raw_material in associated_raw_materials:
#                 raw_material_id = raw_material[0]
#                 cursor.execute(
#                     "SELECT QUANTITY FROM RAWMATERIALS WHERE MATERIALID = ?",
#                     (raw_material_id,),
#                 )
#                 raw_material_quantity = cursor.fetchone()[0]

#                 if raw_material_quantity <= 0:
#                     missing_raw_materials.append(raw_material_id)

#             # Check for missing packaging materials
#             cursor.execute(
#                 "SELECT PACKAGINGMATERIALID FROM PACKAGINGMATERIALASSOCIATION WHERE CODE = ?",
#                 (product_code,),
#             )
#             associated_packaging_materials = cursor.fetchall()

#             for packaging_material in associated_packaging_materials:
#                 packaging_material_id = packaging_material[0]
#                 cursor.execute(
#                     "SELECT QUANTITY FROM PACKAGINGMATERIALS WHERE MATERIALID = ?",
#                     (packaging_material_id,),
#                 )
#                 packaging_material_quantity = cursor.fetchone()[0]

#                 if packaging_material_quantity <= 0:
#                     missing_packaging_materials.append(packaging_material_id)

#             if missing_raw_materials or missing_packaging_materials:
#                 # There are missing raw materials or packaging materials
#                 availability_info[product_code] = {
#                     "available_quantity": current_quantity,
#                     "status": f"Cannot Produce - Insufficient Materials. Need {shortage_quantity} More",
#                     "missing_raw_materials": missing_raw_materials,
#                     "missing_packaging_materials": missing_packaging_materials,
#                 }
#             else:
#                 # All required materials are available
#                 availability_info[product_code] = {
#                     "available_quantity": current_quantity,
#                     "status": f"Not Enough Finished Products. Can Potentially Produce or Buy {shortage_quantity} More",
#                 }

#     cursor.close()
#     return availability_info




@app.route('/work_order_status', methods=['GET', 'POST'])
def work_order_status():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).", "info"))
            return render_template('work_order_status.html', header=getheader('WORK_ORDERS_INFO'), data=getdata('WORK_ORDERS_INFO'), contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'))
        
        if request.method == 'POST':
            # Collect customer information from the form
            contact_name = request.form['contact_name']
            status_update = request.form['status_update']

            # Check if the customer already exists based on the company name
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM WORK_ORDERS_INFO WHERE CONTACT_NAME = ?", (contact_name,))
            existing_customer_count = cursor.fetchone()

            if existing_customer_count:
                # Customer Does Have a WO so update STATUS to 'In-Progress' or 'Completed'.
                cursor.execute("UPDATE WORK_ORDERS_INFO SET STATUS = ? WHERE CONTACT_NAME = ?", (status_update, contact_name))
                conn.commit()
                flash(("Customer '{}' Word Order Updated To '{}' Successfully!".format(contact_name, status_update), "success"))
                cursor.close()
                audit_trail_change(session.get('username'), "Work Order Status","Customer '{}' Word Order Updated To '{}' Successfully!".format(contact_name, status_update))
            else:
                flash(("Customer '{}' Does Not Have A Work Order!".format(contact_name), "info"))
                cursor.close()

        return render_template('work_order_status.html', header=getheader('WORK_ORDERS_INFO'), data=getdata('WORK_ORDERS_INFO'), contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'))
    else:
        return redirect(url_for('login'))  # Redirect to the login page if not logged in


@app.route('/create_new_customer', methods=['GET', 'POST'])
def create_new_customer():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('create_new_customer.html', header=getheader('CUSTOMERS'), data=getdata('CUSTOMERS'))
        
        if request.method == 'POST':
            # Collect customer information from the form
            contact_name = request.form['contact_name']
            company_name = request.form['company_name']
            phone_number = request.form['phone_number']
            email_address = request.form['email_address']
            shipping_address = request.form['shipping_address']

            # Check if the customer already exists based on the company name
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM CUSTOMERS WHERE COMPANY_NAME = ?", (company_name,))
            existing_customer_count = cursor.fetchone()[0]

            if existing_customer_count == 0:
                # Customer does not exist, insert new customer
                cursor.execute("INSERT INTO CUSTOMERS (CONTACT_NAME, COMPANY_NAME, PHONE_NUMBER, EMAIL_ADDRESS, SHIPPING_ADDRESS, REMOVED) VALUES (?, ?, ?, ?, ?, ?)",
                            (contact_name, company_name, phone_number, email_address, shipping_address, 'F'))
                conn.commit()
                cursor.close()
                flash(("Customer {} Added Successfully!.".format(contact_name), "success"))
                audit_trail_change(session.get('username'), "Added New Customer", "Customer {} Added Successfully!.".format(contact_name))
                return render_template('create_new_customer.html', header=getheader('CUSTOMERS'), data=getdata('CUSTOMERS'))
            else:
                flash(("Customer {} Already Exists!.".format(contact_name), "info"))
                cursor.close()
                return render_template('create_new_customer.html', header=getheader('CUSTOMERS'), data=getdata('CUSTOMERS'))

        return render_template('create_new_customer.html', header=getheader('CUSTOMERS'), data=getdata('CUSTOMERS'))  # You need to create an HTML template for the form
    else:
        return redirect(url_for('login'))  # Redirect to the login page if not logged in
    

@app.route('/remove_customer', methods=['GET', 'POST'])
def remove_customer():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('remove_customer.html', header=getheader('CUSTOMERS'), data=getdata('CUSTOMERS'), contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'))
        
        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function
        if user_privilege not in ['Admin', 'Manager']:
            flash(("You As A {} Do Not Have The Required Privileges To Perform This Action Ask A Manager.".format(user_privilege), "info"))
            return render_template('remove_customer.html', header=getheader('CUSTOMERS'), data=getdata('CUSTOMERS'), contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'))
        
        if request.method == 'POST':
            # Collect customer information from the form
            contact_name = request.form['contact_name']

            # Check if the customer already exists based on the company name
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM CUSTOMERS WHERE CONTACT_NAME = ? AND REMOVED = 'F'", (contact_name,))
            existing_customer = cursor.fetchone()

            if not existing_customer:
                # Customer does not exist, insert new customer
                flash(("Customer '{}' Does Not Exist or May Already Have Been Removed!".format(contact_name), "info"))
                return render_template('remove_customer.html', header=getheader('CUSTOMERS'), data=getdata('CUSTOMERS'), contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'))
    
            else:
                cursor.execute("UPDATE CUSTOMERS SET REMOVED = 'T' WHERE CONTACT_NAME = ?", (contact_name))
                cursor.commit()
                cursor.close()
                flash(("Customer '{}' Removed!".format(contact_name), "success"))
                audit_trail_change(session.get('username'), "Removed Customer", "Customer '{}' Removed!".format(contact_name))
                return render_template('remove_customer.html', header=getheader('CUSTOMERS'), data=getdata('CUSTOMERS'), contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'))
    
        return render_template('remove_customer.html', header=getheader('CUSTOMERS'), data=getdata('CUSTOMERS'), contact_list=sdropDown('CUSTOMERS', 'CONTACT_NAME'))  # You need to create an HTML template for the form
    else:
        return redirect(url_for('login'))  # Redirect to the login page if not logged in
    

@app.route('/restore_customer', methods=['GET', 'POST'])
def restore_customer():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only View The Tables In This Program. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('restore_customer.html', header=getheader('CUSTOMERS'), data=getdata('CUSTOMERS'), contact_list=inversesdropDown('CUSTOMERS', 'CONTACT_NAME'))
        
        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function
        if user_privilege not in ['Admin', 'Manager']:
            flash(("You As A {} Do Not Have The Required Privileges To Perform This Action Ask A Manager.".format(user_privilege), "info"))
            return render_template('restore_customer.html', header=getheader('CUSTOMERS'), data=getdata('CUSTOMERS'), contact_list=inversesdropDown('CUSTOMERS', 'CONTACT_NAME'))
        
        if request.method == 'POST':
            # Collect customer information from the form
            contact_name = request.form['contact_name']

            # Check if the customer already exists based on the company name
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM CUSTOMERS WHERE CONTACT_NAME = ? AND REMOVED = 'T'", (contact_name,))
            existing_customer = cursor.fetchone()

            if not existing_customer:
                # Customer does not exist, insert new customer
                flash(("Customer '{}' Does Not Exist or May Already Have Been Restored!".format(contact_name), "info"))
                return render_template('restore_customer.html', header=getheader('CUSTOMERS'), data=getdata('CUSTOMERS'), contact_list=inversesdropDown('CUSTOMERS', 'CONTACT_NAME'))
    
            else:
                cursor.execute("UPDATE CUSTOMERS SET REMOVED = 'F' WHERE CONTACT_NAME = ?", (contact_name))
                cursor.commit()
                cursor.close()
                flash(("Customer '{}' Restored!".format(contact_name), "success"))
                audit_trail_change(session.get('username'), "Restored Customer", "Customer '{}' Does Not Exist or May Already Have Been Restored!".format(contact_name))
                return render_template('restore_customer.html', header=getheader('CUSTOMERS'), data=getdata('CUSTOMERS'), contact_list=inversesdropDown('CUSTOMERS', 'CONTACT_NAME'))
    
        return render_template('restore_customer.html', header=getheader('CUSTOMERS'), data=getdata('CUSTOMERS'), contact_list=inversesdropDown('CUSTOMERS', 'CONTACT_NAME'))  # You need to create an HTML template for the form
    else:
        return redirect(url_for('login'))  # Redirect to the login page if not logged in
    
'''

    Below is code endpoints for all things related user options

'''

@app.route('/user_options')
def user_options():
    '''
    index function contains the logic to render the user_options.
    '''
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Can Only Change Your Password Here. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('user_options.html')
        
        return render_template('user_options.html')
    else:
        return redirect(url_for('login'))  # Redirect to the login page if not logged in


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' in session:
        
        if request.method == 'POST':
            # Retrieve current user's username
            current_username = session['username']

            # Retrieve the current password and new password from the form
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_new_password = request.form['confirm_new_password']

            # Query the database to check the current password
            cursor = conn.cursor()
            cursor.execute("SELECT PASSWORD FROM USERS WHERE USERNAME = ?", (current_username,))
            stored_password = cursor.fetchone()

            if (hash_password(new_password) == hash_password(confirm_new_password)):
                if stored_password and stored_password[0] == hash_password(current_password):
                    # Update the password in the database with the new password
                    cursor.execute("UPDATE USERS SET PASSWORD = ? WHERE USERNAME = ?", (hash_password(new_password), current_username))
                    conn.commit()
                    flash(("Password Changed Successfully.", "success"))
                    audit_trail_change(session.get('username'), "Password Changed", "Change Password Successful")
                else:
                    flash(("Incorrect Current Password. Password Not Changed.", "info"))
            else:
                flash(("New Password Fields Did Not Match. Password Not Changed.", "info"))

            cursor.close()

        return render_template('change_password.html')
    else:
        return redirect(url_for('login'))


@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Do Not Have Access To Create A New User Page. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('user_options.html')
        
        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function
        if user_privilege not in ['Admin']:
            flash(("You As A {} Do Not Have The Required Privileges To Create A User. Ask An Admin.".format(user_privilege), "info"))
            return render_template('user_options.html')
        
        privilege_allowed_to_set = ['Read-Only-User', 'User', 'Manager']

        if request.method == 'POST':
            # Retrieve the current password and new password from the form
            new_username = request.form['new_username']
            privilege_set = request.form['privilege_set']
            new_password = request.form['new_password']
            confirm_new_password = request.form['confirm_new_password']

            # Query the database to check the current password
            cursor = conn.cursor()
            cursor.execute("SELECT USERNAME FROM USERS WHERE USERNAME = ?", (new_username,))
            stored_username = cursor.fetchone()

            if stored_username:
                flash(("Username Already Exists.", "info"))
                cursor.close()
                return render_template('create_user.html', list_privilege=privilege_allowed_to_set, headers=getheader("USERS"), data=getdata("USERS"))
            
            if hash_password(new_password) == hash_password(confirm_new_password):
                # Update the password in the database with the new password
                cursor.execute("INSERT INTO USERS (USERNAME, PASSWORD, PRIVEILEGE, REMOVED) VALUES (?, ?, ?, ?)", (new_username, hash_password(new_password), privilege_set, 'F'))
                conn.commit()
                flash(("User Created successfully.", "success"))
                cursor.close()
                audit_trail_change(session.get('username'), "Create User", "New User {} Created Successfully".format(new_username))
                return render_template('create_user.html', list_privilege=privilege_allowed_to_set, headers=getheader("USERS"), data=getdata("USERS"))
            else:
                flash(("Password Fields Did Not Match.", "info"))
                cursor.close()
                return render_template('create_user.html', list_privilege=privilege_allowed_to_set, headers=getheader("USERS"), data=getdata("USERS"))  
        return render_template('create_user.html', list_privilege=privilege_allowed_to_set, headers=getheader("USERS"), data=getdata("USERS"))  
    else:
        return redirect(url_for('login'))

@app.route('/manage_privileges', methods=['GET', 'POST'])
def manage_privileges():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Do Not Have Access To Access Privilege Page. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('user_options.html')
        
        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function
        if user_privilege not in ['Admin']:
            flash(("You As A {} Do Not Have The Required Privileges To Access Privileges. Ask An Admin.".format(user_privilege), "info"))
            return render_template('user_options.html')
        
        privilege_allowed_to_set = ['Read-Only-User', 'User', 'Manager', 'Admin']

        if request.method == 'POST':
            # Retrieve the current password and new password from the form
            userName = request.form['new_username']
            privilege_set = request.form['privilege_set']

            # Query the database to check the current password
            cursor = conn.cursor()
            cursor.execute("SELECT USERNAME FROM USERS WHERE USERNAME = ?", (userName,))
            stored_username = cursor.fetchone()

            if not stored_username:
                flash(("Username Does Not Exists.", "info"))
                cursor.close()
                return render_template('manage_privileges.html', list_privilege=privilege_allowed_to_set, headers=getheader("USERS"), data=getdata("USERS"), usernames=getDropDownForNonAdminUsers())
            
            # cursor.execute("SELECT PRIVEILEGE FROM USERS WHERE USERNAME = ?", (userName,))
            # stored_priv = cursor.fetchone()

            # if stored_priv and stored_priv[0] == 'Admin':
            #     flash(("Cannnot Change Admin Priveiledge.", "info"))
            #     cursor.close()
            #     return render_template('manage_privileges.html', list_privilege=privilege_allowed_to_set, headers=getheader("USERS"), data=getdata("USERS"), usernames=getDropDownForNonAdminUsers())
            
            # Update the password in the database with the new password
            cursor.execute("UPDATE USERS SET PRIVEILEGE = ? WHERE USERNAME = ?", (privilege_set, userName))
            conn.commit()
            flash(("Username: {} privilege updated successfully to: {}.".format(userName, privilege_set), "success"))
            cursor.close()
            audit_trail_change(session.get('username'), "Manage User Privileges", "Username: {} privilege updated successfully to: {}.".format(userName, privilege_set))
        return render_template('manage_privileges.html', list_privilege=privilege_allowed_to_set, headers=getheader("USERS"), data=getdata("USERS"), usernames=getDropDownForNonAdminUsers())
    else:
        return redirect(url_for('login'))



@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Do Not Have Access To Manage Users Page. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('user_options.html')
        
        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function
        if user_privilege not in ['Admin']:
            flash(("You As A {} Do Not Have The Required Privileges To Perform Manage Users. Ask An Admin.".format(user_privilege), "info"))
            return render_template('user_options.html')

        if request.method == 'POST':
            userName = request.form.get('username')
            action = request.form.get('action')

            cursor = conn.cursor()
            cursor.execute("SELECT USERNAME FROM USERS WHERE USERNAME = ?", (userName,))
            stored_username = cursor.fetchone()

            if not stored_username:
                flash(("Username Does Not Exists.", "info"))
                cursor.close()
                return render_template('manage_users.html', headers=getheader("USERS"), data=getdataForUsers(), usernames=getDropDownForNonAdminUsers2())
            
            if userName and action in ['delete', 'restore']:
                if action == 'delete':

                    cursor.execute("SELECT REMOVED FROM USERS WHERE USERNAME = ?", (userName,))
                    removed = cursor.fetchone()

                    if removed[0] == 'T':
                        flash(("Username Already Deleted.", "info"))
                        cursor.close()
                        return render_template('manage_users.html', headers=getheader("USERS"), data=getdataForUsers(), usernames=getDropDownForNonAdminUsers2())
            
                    # Update the 'REMOVED' field to 'T' to remove the user
                    cursor.execute("UPDATE USERS SET REMOVED = ? WHERE USERNAME = ?", ('T', userName))
                    cursor.commit()
                    cursor.close()
                    flash(("Username: {} Got Deleted.".format(userName), "success"))
                else:

                    cursor.execute("SELECT REMOVED FROM USERS WHERE USERNAME = ?", (userName,))
                    removed = cursor.fetchone()

                    if removed[0] == 'F':
                        flash(("Username Already Restored.", "info"))
                        cursor.close()
                        return render_template('manage_users.html', headers=getheader("USERS"), data=getdataForUsers(), usernames=getDropDownForNonAdminUsers2())
                    
                    # Update the 'REMOVED' field to 'F' to restore the user
                    cursor.execute("UPDATE USERS SET REMOVED = ? WHERE USERNAME = ?", ('F', userName))
                    cursor.commit()
                    cursor.close()
                    flash(("Username: {} Got Restored.".format(userName), "success"))
                    audit_trail_change(session.get('username'), "Manage User Privileges", "Username: {} Got Restored.".format(userName))

        return render_template('manage_users.html', headers=getheader("USERS"), data=getdataForUsers(), usernames=getDropDownForNonAdminUsers2())
    else:
        return redirect(url_for('login'))



@app.route('/audit_trail', methods=['GET', 'POST'])
def audit_trail():
    if 'username' in session:

        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function

        if user_privilege == 'Read-Only-User':
            flash(("You As A 'Read-Only-User' Do Not Have Access To Audit Trail Page. (Contact Admin/IT If Something is Wrong).".format(user_privilege), "info"))
            return render_template('user_options.html')
        
        # Check if the user has the required privileges (Admin or Manager)
        user_privilege = get_user_privilege(session['username'])  # You need to implement get_user_privilege function
        if user_privilege not in ['Admin']:
            flash(("You As A {} Do Not Have The Required Privileges To Perform Manage Users. Ask An Admin.".format(user_privilege), "info"))
            return render_template('user_options.html')

        if request.method == 'POST':
            return render_template('audit_trail.html', headers=getheader("AUDIT_TRAIL"), data=getAuditTrail())
        return render_template('audit_trail.html', headers=getheader("AUDIT_TRAIL"), data=getAuditTrail())
    else:
        return redirect(url_for('login'))



if __name__ == '__main__':
    # print(hash_password('123'))
    # print(hash_password('abc'))
    #print(hash_password('Reader0'))
    app.run(debug=False)
