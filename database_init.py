import sqlite3

def initialize_db():
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()

#     # Tabela użytkowników
#     cursor.execute('''
#         CREATE TABLE IF NOT EXISTS users (
#             id INTEGER PRIMARY KEY AUTOINCREMENT,
#             username TEXT UNIQUE NOT NULL,
#             email TEXT UNIQUE,
#             password_hash TEXT NOT NULL,
#             public_key TEXT NOT NULL,
#             token TEXT NOT NULL
#         )
#     ''')

    # Tabela notatek
    cursor.execute('''
    ALTER TABLE notes ADD random_id INTEGER;
    ''')
        # CREATE TABLE IF NOT EXISTS notes (
        #     id INTEGER PRIMARY KEY AUTOINCREMENT,
        #     title TEXT NOT NULL,
        #     content TEXT NOT NULL,
        #     is_public INTEGER NOT NULL DEFAULT 0,
        #     shared_with TEXT NULL,
        #     is_encrypted INTEGER NOT NULL DEFAULT 0,
        #     password_hash TEXT NULL,
        #     owner_username TEXT NOT NULL,
        #     signature TEXT NULL,
        #     FOREIGN KEY (owner_username) REFERENCES users (username),
        #     FOREIGN KEY (shared_with) REFERENCES users (username)
        # )
    # ''')

    conn.commit()
    conn.close()

if __name__ == "__main__":
    initialize_db()
