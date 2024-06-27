from app import app
from user.models import User

"""
Ces routes ne rendent pas de page web html, ils servent seulement a comuniquer pour, ouvrir ou fermer une session
et communiquer avec models.py
"""

@app.route('/user/signout')
def signout():
  return User().signout()

@app.route('/user/login', methods=['POST'])
def login():
  return User().login()