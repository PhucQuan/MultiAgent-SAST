import sqlite3

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Lỗ hổng Database (Sink nằm ở đây)
def get_user_info(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Code ẩu: Ghép chuỗi SQL trực tiếp thay vì tham số hóa
    # Sink: cursor.execute()
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        return dict(user) if user else {"error": "User not found"}
    except Exception as e:
        conn.close()
        return {"error": str(e)}
