import os
from pymongo import MongoClient
import string
import random

"""Variables d'environnement pour cacher nos adresses Mongo et son certificat"""
URL = os.environ.get('url')
certificate = os.environ.get('cert')

"""
rend une collection dans une base de donnees
"""
def get_collections(database):
    try:
        client = MongoClient(URL,
                             tls=True,
                             tlsCertificateKeyFile=certificate)
        db = client[database]
        return db
    except Exception as e:
        print(e)
        return None

"""
Elle est utilise seulement, pour obtenir une liste des clients, apartir de notre base de donnees
"""
def get_documents(collection, name):
    try:
        documents = collection[name].find()
        return documents

    except Exception as e:
        print(e)

"""
elle retourne toutes les parametres de la polique de mot de passe courant
"""
def get_configuration():
    try:
        client = MongoClient(URL,
                             tls=True,
                             tlsCertificateKeyFile=certificate)
        db = client['configuration']
        configuration = db['configuration'].find_one()
        numerique = configuration["numerique"]
        majuscule = configuration["majuscule"]
        minuscule = configuration["minuscule"]
        caractere = configuration["caractere"]
        interdiction = configuration["interdiction"]
        longMinimum = configuration["longMinimum"]
        longMaximum = configuration["longMaximum"]
        tentative = configuration["tentative"]
        delai = configuration["delai"]
        return numerique, majuscule, minuscule, caractere, interdiction, longMinimum, longMaximum, tentative, delai
    except Exception as e:
        print(e)
        return None

"""
elle verifie la si la complexité de mot de passe et respecté selon la polique actuel de mot de passe
"""
def password_complexity(password):
    numeriqueDb, majusculeDb, minusculeDb, caractereDb, interdictionDb, \
        longMinimumDb, longMaximumDb, tentativeDb, delaiDb = get_configuration()

    # Vérification de la longueur minimale
    if len(password) < int(longMinimumDb):
        return False, ("longMinimum", longMinimumDb)

    # Vérification de la longueur maximale
    if len(password) > int(longMaximumDb):
        return False, ("longMaximum", longMaximumDb)

    # Vérification des chiffres
    if numeriqueDb == "on" and not any(c.isdigit() for c in password):
        return False, ("numerique", numeriqueDb)

    # Vérification des majuscules
    if majusculeDb == "on" and not any(c.isupper() for c in password):
        return False, ("majuscule", majusculeDb)

    # Vérification des minuscules
    if minusculeDb == "on" and not any(c.islower() for c in password):
        return False, ("minuscule", minusculeDb)

    # Vérification des caractères spéciaux
    if caractereDb == "on" and not any(c in "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~" for c in password):
        return False, ("Caractere", caractereDb)

    # Toutes les conditions sont remplies
    return True, True

"""
permet de generer un mot de passe, en respectant les politiques actuelles
"""
def generate_password():
    numeriqueDb, majusculeDb, minusculeDb, caractereDb, interdictionDb, \
        longMinimumDb, longMaximumDb, tentativeDb, delaiDb = get_configuration()
    # Define character sets based on the given parameters
    if numeriqueDb is not None:
        digits = string.digits
    else:
        digits = ""
    if majusculeDb is not None:
        uppercase_letters = string.ascii_uppercase
    else:
        uppercase_letters = ""
    if minusculeDb is not None:
        lowercase_letters = string.ascii_lowercase
    else:
        lowercase_letters = ""
    if caractereDb is not None:
        special_chars = string.punctuation
    else:
        special_chars = ""

    # Combine the character sets into a single string
    allowed_chars = digits + uppercase_letters + lowercase_letters + special_chars

    # Ensure that the password length is within the given bounds
    password_length = random.randint(longMinimumDb, longMaximumDb)

    # Generate a random password using the allowed characters
    password = "".join(random.choice(allowed_chars) for _ in range(password_length))

    return password

"""
elle affiche donne un objet html pour afficher la polique actuel de mot de passe sur le front end
"""
def display_policy():
    numerique, majuscule, minuscule, caractere, interdiction, longMinimum, longMaximum, tentative, delai = get_configuration()

    if numerique == "on":
        numerique = "Nombre "
    else:
        numerique = " "
    if majuscule == "on":
        majuscule = "Majuscule "
    else:
        majuscule = " "
    if minuscule == "on":
        minuscule = "Minuscule "
    else:
        minuscule = " "
    if caractere == "on":
        caractere = "Caractère spéciale "
    else:
        caractere = " "

    policy = "Votre mot de passe doit contenir un de chaque type:<br>" \
             "<b>{}</b><br><b>{}</b><br><b>{}</b><br><b>{}</b>.<br>" \
             "Et doit être d'une longueur entre <b>{}</b> et <b>{}</b>".format(numerique, majuscule, minuscule,
                                                                               caractere, longMinimum,
                                                                               longMaximum)
    return policy
