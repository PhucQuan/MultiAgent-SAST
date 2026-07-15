import sqlite3
from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect('example.db', check_same_thread=False)

def get_user_data(user_id):
    # This is a vulnerable function (Sink)
    query = f"SELECT * FROM users WHERE id={user_id}"
    cursor = db.cursor()
    cursor.execute(query)
    return cursor.fetchall()

@app.route('/profile')
def profile():
    # Taint Source enters here
    user_id = request.args.get('id')
    # Taint propagates to the vulnerable function
    data = get_user_data(user_id)
    return str(data)

if __name__ == '__main__':
    app.run()
