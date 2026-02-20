import os

def read_system_file(filename):
    """
    Tiện ích dùng chung để đọc file cấu hình
    """
    base_dir = "/var/www/uploads/"
    
    # Path Traversal: Nối chuỗi trực tiếp mà không kiểm tra (sanitize)
    file_path = base_dir + filename
    
    try:
        # Sink: open()
        with open(file_path, 'r') as f:
            return f.read()
    except Exception as e:
        return f"File error: {str(e)}"
