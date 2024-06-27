import os
from passlib.handlers.pbkdf2 import pbkdf2_sha256


#Variables d'environnement pour caché nos addresses mongo
URL = os.environ.get('url')
certificate = os.environ.get('cert')

#permet de hasher un mot de passe
def hash_password(password):
    # Salt aleatoire
    salt = os.urandom(16)

    # utiliser PBKDF2 avec 100,000 iterations
    hashed_password = pbkdf2_sha256.hash(password, salt=salt, rounds=100000)

    # combiner le salt et le password
    salted_password = salt.hex() + ":" + hashed_password

    return salted_password

#permet de verifier un mot de passe et son hashcode
def verify_password(password, hashed_password):
    salt, stored_hash = hashed_password.split(":")
    calculated_hash = pbkdf2_sha256.hash(password, salt=bytes.fromhex(salt), rounds=100000)

    return calculated_hash == stored_hash
