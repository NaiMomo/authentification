import datetime
import os

from flask import Flask, render_template, session, redirect, request, abort, flash, url_for
from functools import wraps
from pymongo import MongoClient
import db_ops
from admin_ops import get_collections, get_documents, password_complexity, generate_password, \
    display_policy
from db_ops import hash_password
from init_db import make_user, make_configuration

"""
URL Variable d'environnement pour securiser le URL mongoDB
"""

URL = os.environ.get('url')
app = Flask(__name__)
app.secret_key = b'\xcc^\x91\xea\x17-\xd0W\x03\xa7\xf8J0\xac8\xc5'

# Connection a la base de donnees Mongo
client = MongoClient(URL,
                     tls=True,
                     tlsCertificateKeyFile=os.environ.get(
                         'cert'))  # Certificat camouflé dans une variable d'environnment

db = client.users
db_config = client.configuration

'''
login_requiered()
Cette fonction est cité dans le routing @login_required
elle oblige les utilisateur a se loger avant d'avoir accès aux differentes pafes

'''


# Decorators
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect('/')

    return wrap


# Routes
from user import routes

"""
icon affiché dans l'onglet du browser
"""
@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('favicon.svg')

"""
    Page d'accueuil home (authentification)
"""
@app.route('/')
def home():
    return render_template('home.html')


"""
dashboard()
Une fois les utilisateurs sont validés, ils sont dirigés vers les differentes pages dont ils ont autorisés.
"""


@app.route('/dashboard/', methods=('GET', 'POST'))
@login_required
def dashboard():
    # Si un utilisateur a un mot de passe expiré il coincé sur une page de changement de mot de passe
    if session['user']['expired_psw']:
        policy = display_policy()
        return render_template('forced_update.html',
                               show_password_update=True, policy=policy)

    # Si l'utilisateur possede un role admin il sera dirigé vers adminView

    if session['user']['role'] == 'admin':
        return render_template('adminView.html')

    # Si l'utilisateur possede un role employé il sera dirigé vers la vue correspondante

    if session['user']['role'] == 'residentiel' or session['user']['role'] == 'affaires':
        return render_template('employee_view.html')

    return redirect(url_for('index'))


"""
adminView()
Ici on permet à aux administrateur de faire tout ce qu'ils veulent,
adminView.html utilise un dropdown pour faire les operations, lorsqu'un admin
appuie sur une option, il appel la methode POST ici
"""


@app.route('/adminView', methods=('GET', 'POST'))
@login_required
def admin_view():
    # Si l'utilisateur n'est pas admin, il sera "forbidden" interdit de voir cette page
    if session['user']['role'] != 'admin':
        abort(403)

    # si l'administrateur appui sur le dropdown
    if session['user']['role'] == 'admin' and request.method == 'POST':
        order_by = request.form.get('orderBy')
        if order_by == 'c_affaires':

            collection_cli = get_collections("clients")
            users = get_documents(collection_cli, 'affaires')

            return render_template('adminView.html',
                                   users=users, show_clients=True, show_users=False)
        elif order_by == 'c_residentiel':
            collection_cli = get_collections("clients")
            users = get_documents(collection_cli, 'residentiel')
            return render_template('adminView.html', users=users, show_clients=True,
                                   show_users=False)

        elif order_by == 'utilisateurs':
            # utilisateurs residentiels
            collection_cli = get_collections("users")
            users = get_documents(collection_cli, 'users')
            password = generate_password()
            return render_template('adminView.html', users=users,
                                   show_clients=False, show_users=True, new_pass=password)

        elif order_by == 'password_policy':

            policy = display_policy()
            return render_template('adminView.html', users=None,
                                   show_clients=False, show_users=False, show_password_policy=True, policy=policy)

        elif order_by == 'password_update':
            policy = display_policy()
            return render_template('adminView.html', users=None,
                                   show_clients=False, show_users=False, show_password_update=True, policy=policy)

    else:
        return render_template('adminView.html')


"""
allow_admin_op()
lorsqu'un administrateur, à partir de la table d'utilisateurs, déclanche une action (dropdown option)
on lit cet et on le traite en conséquence, les actions ne seront validés que si le mot de passe est confirmé
"""


@app.route('/allow_admin_op', methods=['POST'])
@login_required
def allow_admin_op():
    # If user is not logged in or is not an admin, return a 403 error
    if session['user']['role'] != 'admin':
        abort(403)

    # verifier le password soumis sur la boite de confirmation
    confirmed = db_ops.verify_password(request.form.get('confirmation'), session['user']['password'])
    action = request.form.get('action')
    affected_user = request.form.get('username')

    if confirmed:
        if action == "admin_role":
            query = {"username": affected_user}
            new_role = {"$set": {"role": 'admin'}}
            db['users'].update_one(query, new_role)

        if action == "resi_role":
            query = {"username": affected_user}
            new_role = {"$set": {"role": 'residentiel'}}
            db['users'].update_one(query, new_role)
            flash('Role modifié avec succès')

        if action == "business_role":
            query = {"username": affected_user}
            new_role = {"$set": {"role": 'affaires'}}
            db['users'].update_one(query, new_role)

        if action == "reset_pass":
            # faire un nouveau mot de passe
            new_password = generate_password()
            query = {"username": affected_user}
            new_update = {"$set": {"blocked": False, "expired_psw": True, "loginAttempt": 0,
                                   "password": hash_password(new_password)}}

            db['users'].update_one(query, new_update)

            # save password in a file
            file_path = os.environ.get('user_temp_pass') + '_' + affected_user + ".txt"
            with open(file_path, "w") as f:
                f.write(new_password)

    new_admin_act = {"user": session['user']['username'], "action": action, "affected_user": affected_user}
    db_config['admin_actions'].insert_one(new_admin_act)

    return render_template('adminView.html')


"""
add_new_user()
Comme son nom l'indique, elle permet a un administrateur d'ajouter un utilisateur, 
L'administrateur doit choisir un mot de passe pour le nouveau utilisateur, tout en respectant les 
politiques de mot de passe
"""


@app.route('/add_new_user', methods=('GET', 'POST'))
@login_required
def add_new_user():
    if session['user']['role'] != 'admin':
        # If user is not logged in or is not an admin, return a 403 error
        abort(403)

    if request.method == 'POST':
        user = request.form['Utilisateur']
        user_role = request.form['user_role']
        password = request.form['password']
        password_confirmation = request.form['passwordConfirmation']
        confirmation = request.form['confirmation']
        session_password = session['user']['password']
        policy = display_policy()

        if user == "" or password == "":
            flash('Veuillez remplir toutes les champs')
            return render_template('adminView.html', users=None,
                                   tab_title="", show_new_user_form=True, show_clients=False, show_users=False,
                                   show_policy=True, policy=policy)
        if password_confirmation != password:
            flash("Le mot de passe ne correspond pas")
            return render_template('adminView.html', users=None,
                                   tab_title="", show_new_user_form=True, show_clients=False, show_users=False,
                                   show_policy=True, policy=policy)
        if not db_ops.verify_password(confirmation, session_password):
            flash("Veuillez vérifier votre mot de passe et réessayer")
            return render_template('adminView.html', users=None,
                                   tab_title="", show_new_user_form=True, show_clients=False, show_users=False,
                                   show_policy=True, policy=policy)
        else:
            check_complexity, value = password_complexity(password)
            if check_complexity:
                hash_pass = hash_password(password)
                make_user(user, hash_pass, user_role)
                flash("Utilisateur ajouté avec succès")
                return render_template('adminView.html', users=None,
                                       tab_title="", show_new_user_form=True, show_clients=False, show_users=False,
                                       show_policy=True,
                                       policy=policy)
            else:
                flash('Mot passe : critères non remplis')
                return render_template('adminView.html', users=None,
                                       tab_title="", show_new_user_form=True, show_clients=False, show_users=False,
                                       show_policy=True, policy=policy)


    else:
        policy = display_policy()
        return render_template('adminView.html', users=None,
                               tab_title="", show_new_user_form=True, show_clients=False, show_users=False,
                               show_policy=True,
                               policy=policy)

"""
employee_view()
Elle permet a un utilisateur courant de voir ses clients et changer ses mot de passe seulement
"""
@app.route('/employee_view', methods=('GET', 'POST'))
@login_required
def employee_view():
    if session['user']['role'] not in ['residentiel', 'affaires']:
        # If user is not logged in or does not have the required role, return a 403 error
        abort(403)
    if request.method == 'POST':
        order_by = request.form.get("orderBy")
        if order_by == 'afficher_clients':
            if session['user']['role'] in ['residentiel', 'affaires']:
                collection_cli = get_collections("clients")
                users = get_documents(collection_cli, session['user']['role'])
                return render_template('employee_view.html', tab_title='Clients',
                                       users=users, show_clients=True)

        if order_by == 'password_update':
            policy = display_policy()
            return render_template('employee_view.html',
                                   show_password_update='True', policy=policy)

    else:
        return render_template('employee_view.html')

"""
password_update()
Ici on met a jour le mot de passe, et c'est ici ou on fait le travail fort.
Ici on fait appel a plusieurs fonctions qui valident la politique actuel de mot de passe.
Les fonctions se trouvent dans admin_ops.py
"""

@app.route('/password_update', methods=('GET', 'POST'))
@login_required
def password_update():
    render_html = None  # verify if its a good idea
    view = None
    if session['user']['role'] not in ['admin', 'residentiel', 'affaires']:
        # If user is not logged in or is not an admin, return a 403 error
        abort(403)
    if request.method == 'POST':
        ancienMdp = request.form['ancienMdp']
        password = request.form['password']
        confirmer = request.form['confirmer']
        session_password = session['user']['password']
        session_user = session['user']['username']
        session_role = session['user']['role']
        old_psw = session['user']['old_psw']
        if session_role in ['residentiel', 'affaires']:
            render_html = 'employee_view.html'
            view = 'employee_view'
        if session_role in ['admin']:
            render_html = 'adminView.html'
            view = 'admin_view'

        if not ancienMdp or not password or not confirmer:
            flash('Some fields are missing')
            return render_template(render_html,
                                   show_password_update='True')

        if password != confirmer or db_ops.verify_password(confirmer,
                                                           old_psw):
            flash("Le mot de passe ne correspond pas")
        if not db_ops.verify_password(ancienMdp, session_password):
            flash("Veuillez vérifier votre mot de passe et réessayer")
        if db_ops.verify_password(ancienMdp, session_password):
            new_passwd = password
            ##check complexity
            check_complexity, value = password_complexity(new_passwd)
            if check_complexity:
                new_hashed_pass = hash_password(new_passwd)

                # le mettre a jour
                current_time = datetime.datetime.now()
                timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")
                query = {"username": session_user}
                new_password = {"$set": {"password": new_hashed_pass, "expired_psw": False,
                                         "old_psw": session['user']['password']}}
                passwordChangeDate = {"$set": {"passwordChangeDate": timestamp}}

                db['users'].update_one(query, new_password)
                db['users'].update_one(query, passwordChangeDate)
                flash('Mots de passe changé')

                return redirect(url_for(view))
            else:
                flash('Mot passe inchangé : critères non remplis')

    return render_template(render_html,
                           show_password_update='True')

"""
force_password_update()
Si l'utilisateur a un status de mot de passe expiré on doit le forcer a changer son mot de passe
cela se fait par defaut dans le route "home"
"""
@app.route('/force_password_update', methods=('POST', 'GET'))
@login_required
def force_password_update():
    if session['user'] is None or not session['user']['expired_psw']:
        # If user is not logged in or is not an admin, return a 403 error
        abort(403)
    if request.method == 'POST':
        password = request.form['password']
        confirmer = request.form['confirmer']
        policy = display_policy()
        if password == confirmer:
            if password and not db_ops.verify_password(password, session['user']['old_psw']):
                # écrire dans la base de données
                current_time = datetime.datetime.now()
                time_stamp = current_time.strftime("%Y-%m-%d %H:%M:%S")
                query = {"username": session['user']['username']}
                new_passwd = {"$set": {"password": hash_password(password),
                                       "old_psw": session['user']['old_psw'],
                                       "passwordChangeDate": time_stamp,
                                       "blocked": False,
                                       "loginAttempt": 0,
                                       "expired_psw": False}}
                db['users'].update_one(query, new_passwd)
                flash('Mot de passe modifié avec succès')
                session.clear()
                return redirect(url_for('home'))

            else:
                flash("N'utilisez pas votre ancien mot de passe")
                return render_template('forced_update.html', show_password_update=True, policy=policy)

        else:
            flash('Votre mot de passe n\'est respecte pas les conditions')
            return render_template('forced_update.html', show_password_update=True, policy=policy)
    else:
        session.clear()
        return redirect(url_for('home'))

"""
password_policy() -- dropdown configuration admin
Ici on utilise les functions de db_ops pour connaitre la politique courante, et permettre
au administrateur, de changer la politique actuel de mot de passe s'il veut.
"""
@app.route('/password_policy', methods=('GET', 'POST'))
@login_required
def password_policy():
    if session['user']['role'] != 'admin':
        # If user is not logged in or is not an admin, return a 403 error
        abort(403)
    if request.method == 'POST':
        numerique = request.form.get('numerique')
        majuscule = request.form.get('majuscule')
        minuscule = request.form.get('minuscule')
        caractere = request.form.get('caractere')
        interdiction = request.form.get('interdiction')
        longMinimum = request.form.get('longMinimum')
        longMaximum = request.form.get('longMaximum')
        tentative = request.form.get('tentative')
        delai = request.form.get('delai')
        confirmation = request.form.get('confirmation')  # need to check current user pass?
        session_password = session['user']['password']

        if db_ops.verify_password(confirmation, session_password):
            numerique = numerique or "off"
            majuscule = majuscule or "off"
            minuscule = minuscule or "off"
            caractere = caractere or "off"
            interdiction = interdiction or "off"

            make_configuration(numerique, majuscule, minuscule, caractere, interdiction, longMinimum, longMaximum,
                               tentative, delai)

            flash('Politique mise à jour')

            return render_template('adminView.html', users=None,
                                   tab_title="", show_password_policy=False, show_clients=False, show_users=False)
        else:
            flash("Veuillez vérifier votre mot de passe et réessayer")
            return render_template('adminView.html', users=None, tab_title="", show_password_policy=True,
                                   show_clients=False, show_users=False)

    return render_template('adminView.html', users=None,
                           tab_title="", show_password_policy=True, show_clients=False, show_users=False)


if __name__ == '__main__':
    app.run()
