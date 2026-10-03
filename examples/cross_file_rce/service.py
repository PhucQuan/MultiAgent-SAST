from executor import execute_shell

def process_backup(db_name):
    # Intermediate taint propagation
    backup_cmd = f"mysqldump -u root {db_name} > /tmp/db.sql"
    execute_shell(backup_cmd)
