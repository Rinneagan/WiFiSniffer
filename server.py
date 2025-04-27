from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return '''
    <html><body style="background-color:black; color:red; text-align:center; font-size:50px;">
    <br><br><br><br>
    I'M WATCHING YOU 👀
    </body></html>
    '''

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)