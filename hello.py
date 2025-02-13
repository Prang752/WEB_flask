from flask import Flask

app = Flask(__name__)

@app.route("/japan/tokyo")
def tokyo():
    return "Hello, tokyo in Japan!"

@app.route("/japan/nara")
def nara():
    return "Hello, nara in Japan!"

@app.route("/japan/tokyo")
def chiyoda():
    return "Hello, chiyoda in Japan!"
