from flask import request, abort, render_template, redirect, url_for, flash

from brewCalc import app

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/profile', methods=['GET'])
def profile():
    return render_template('profile.html')

@app.route('/recipes', methods=['GET'])
def recipes():
    return render_template('recipes.html')