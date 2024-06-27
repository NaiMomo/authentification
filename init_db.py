import os
from pymongo import MongoClient
from db_ops import hash_password
import datetime

#Variables d'environnement pour caché nos addresses mongo
URL = os.environ.get('url')
certificate = os.environ.get('cert')

"""conection a une base de donnees mongo"""
def connect_to_mongodb(url, certificat):
    client = MongoClient(url, tls=True, tlsCertificateKeyFile=certificat)
    return client

"""permet de faire un nouveau client (table de client)"""
def make_clients(nom, prenom, role):
    try:
        client = connect_to_mongodb(URL, certificate)
        db = client.clients

        entry = {
            'nom': nom,
            'prenom': prenom,
            'role': role
        }
        if role == 'affaires':
            db.affaires.insert_one(entry)
            return 0
        elif role:
            db.residentiel.insert_one(entry)
            return 0
        else:
            return -1

    except Exception as e:
        print(e)
    return -1

"""permet de faire un nouveau preposé table d'utilisateur"""
def make_user(username, password, role):
    current_time = datetime.datetime.now()
    timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        client = connect_to_mongodb(URL, certificate)
        db = client.users

        entry = {
            'username': username,
            'password': password,
            'role': role,
            'loginAttempt': 0,
            'userCreationDate': timestamp,
            'passwordChangeDate': timestamp,
            'blocked': False,
            'expired_psw': False,
            'old_psw': password
        }

        db.users.insert_one(entry)

        return 0
    except Exception as e:
        print(e)
    return -1

"""Permet d'ecrire dans la base de donnees nos politiques actuelles"""
def make_configuration(numerique, majuscule, minuscule, caractere, interdiction, longMinimum, longMaximum,
                       tentative, delai):
    try:
        client = connect_to_mongodb(URL, certificate)
        db = client.configuration
        delete_database('configuration')
        configuration = {
            'numerique': numerique,
            'majuscule': majuscule,
            'minuscule': minuscule,
            'caractere': caractere,
            'interdiction': interdiction,
            'longMinimum': int(longMinimum),
            'longMaximum': int(longMaximum),
            'tentative': int(tentative),
            'delai': int(delai)
        }
        db.configuration.insert_one(configuration)

        return 0

    except Exception as e:
        print(e)
        return -1

"""Permet de faire une collection dans une base de donnees"""
def create_collection(db_name, collection_name):
    try:
        client = connect_to_mongodb(URL, certificate)
        db = client[db_name]
        collection = db[collection_name]
        return collection
    except Exception as e:
        print(e)
        return None

"""Permet de effacer une base de donnees"""
def delete_database(db_name):
    try:
        client = connect_to_mongodb(URL, certificate)
        client.drop_database(db_name)
        print("Database {} deleted successfully!".format(db_name))
    except Exception as e:
        print(e)


if __name__ == "__main__":
    print("----------- Making databases ---------------")

    # drop databases if it exists
    delete_database('configuration')
    delete_database('passwordRequirements')
    delete_database('clients')
    delete_database('users')

    print("--------- Creating collections --------------")
    # create collections

    create_collection('passwordRequirements', 'complexity')

    create_collection('clients', 'affaires')
    create_collection('clients', 'residentiel')

    create_collection('utilisateurs', 'users')


    print("----------------Making insertions -----------------")
    # uncomment if you ever need to use it
    # drop_users()
    # drop_clients()

    # faire les utilisateurs: TODO: deuxieme param doit etre une le hashing
    adminPassHash = hash_password("Administrateur")
    utilisateur1PassHash = hash_password("Utilisateur1")
    Utilisateur2PassHash = hash_password("Utilisateur2")

    make_user('Administrateur', adminPassHash, 'admin')
    make_user('Utilisateur1', utilisateur1PassHash, 'residentiel')
    make_user('Utilisateur2', Utilisateur2PassHash, 'affaires')

    # faire les clients
    make_clients('george', 'vanier', 'affaires')
    make_clients('jorge', 'basilico', 'residentiel')
    make_clients('francois', 'champlain', 'residentiel')
    make_clients('steve', 'stevenson', 'affaires')
    make_clients('philippe', 'monnier', 'affaires')

    # créer base de donnés de configuration avec des donnés par défault
    numerique = majuscule = minuscule = caractere = interdiction = "on"
    longMinimum = 6
    longMaximum = 20
    tentative = 5
    delai = 3

    make_configuration(numerique, majuscule, minuscule, caractere, interdiction, longMinimum, longMaximum,
                       tentative, delai)
