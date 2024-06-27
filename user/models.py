import time
from datetime import datetime

from flask import jsonify, request, session, redirect
from admin_ops import get_configuration
from app import db
from db_ops import  verify_password


"""
Classe qui s'occupe de contruire un objet qui servira toute au longue de la connection
ou rejet d'une connection
"""
class User:
    """
    si un utilisateur passe par toutes les étapes de validation dans la méthode login
    il sera validé et cette fonction retournera l'objet necessaire pour app.py
    """
    def start_session(self, user):
        session['logged_in'] = True
        session['user'] = user
        print(str(user))
        return user, 200
    '''
        Si pour nettoyer la session courante et rendre user vide
    '''
    def signout(self):
        session.clear()
        return redirect('/')

    """
    processus complet de validation d'un utilisateur.
    ici on determine si t'utilisateur a le droit d'établir une session
    
    """
    def login(self):

        # obtenir les parametres de connection courants
        numerique, majuscule, minuscule, caractere, interdiction, longMinimum, longMaximum, tentative, delai = get_configuration()

        #chercher si l'utilisateur existe
        user = db.users.find_one({
            "username": request.form.get('username') #champ du formulaire login
        })

        #utilisateur non existante donne un json vide et code 401 (non authorisé)
        if user is None:
            time.sleep(delai)
            return jsonify(
                {"error": "Invalid login credentials please wait " + str(delai) + " seconds before retrying"}), 401

        # Utilisateur avec mot de passe expiré se valide seulement si son mot de passe concorde avec le mot de passe temporaire
        if user['expired_psw'] and verify_password(request.form.get('password'), user['password']):
            json_user = {
                "id": str(user["_id"]),
                "username": user["username"],
                "password": user["password"],
                "role": user["role"],
                "loginAttempt": user["loginAttempt"],
                "blocked": user["blocked"],
                "expired_psw": user['expired_psw'],
                "old_psw" : user['old_psw']

            }
            return self.start_session(json_user)

        # Utilisateur est authorisé seulement si son mot de passe corresponde avec un utilisateur existant
        if user and verify_password(request.form.get('password'), user['password']):
            # is him blocked
            if user['blocked'] == True:
                # ecrire dans la base de donnée attempt + 1
                login_attempt = user['loginAttempt'] + 1
                query = {"username": user['username']}
                inc_login_attempt = {"$set": {"loginAttempt": login_attempt}}
                db['users'].update_one(query, inc_login_attempt)

                # Add the LastLoginAttmp field with the current timestamp
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                update_last_login = {"$set": {"LastLoginAttmp": current_time}}
                db['users'].update_one(query, update_last_login)

                self.signout()
                time.sleep(delai)

                return jsonify({"error": "Compte verrouillé, veuillez contacter l'administrateur"}), 401

            json_user = {
                "id": str(user["_id"]),
                "username": user["username"],
                "password": user["password"],
                "role": user["role"],
                "loginAttempt": user["loginAttempt"],
                "blocked": user["blocked"],
                "expired_psw" : user['expired_psw'],
                "old_psw": user['old_psw']

            }
            #ecrire dans la base de donnees, la derniere connexion

            query = {"username": user['username']}
            inc_login_attempt = {"$set": {"loginAttempt": 0}}
            db['users'].update_one(query, inc_login_attempt)

            # Add the LastLoginAttmp field with the current timestamp
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            update_last_login = {"$set": {"LastLoginAttmp": current_time}}
            db['users'].update_one(query, update_last_login)
            return self.start_session(json_user)

        # non valide mais existe, on incremente le nombre d'attempts jusqu'a verrouiller le compte

        elif user and not verify_password(request.form.get('password'), user['password']):

            # ecrire dans la base de donnée attempt + 1
            login_attempt = user['loginAttempt'] + 1
            query = {"username": user['username']}
            inc_login_attempt = {"$set": {"loginAttempt": login_attempt}}
            db['users'].update_one(query, inc_login_attempt)

            # Add the LastLoginAttmp field with the current timestamp
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            update_last_login = {"$set": {"LastLoginAttmp": current_time}}
            db['users'].update_one(query, update_last_login)

            self.signout()
            time.sleep(delai)
            if tentative > user["loginAttempt"]:
                print(str(tentative-user["loginAttempt"])  + "avant le verrouillage du compte")
                return jsonify(
                {"error": str(tentative-user["loginAttempt"])+ " Tentatives restantes "  + "avant le verrouillage du compte"}), 401
                  # Non conected, not blocked
            else:
                query = {"username": user['username']}
                inc_login_attempt = {"$set": {"blocked": True}}
                db['users'].update_one(query, inc_login_attempt)
                return jsonify({"error": "Compte verrouillé, veuillez contacter l'administrateur"}), 401


        else:

            time.sleep(delai)
            return jsonify(
                {"error": "Invalid login credentials please wait "+ str(delai) + " seconds before retrying"}), 401
