import sqlite3
import subprocess


def unsafe_expression():
    expression = input("Expression: ")
    return eval(expression)


def unsafe_command():
    command = input("Command: ")
    return subprocess.run(command, shell=True, capture_output=True, text=True)


def unsafe_lookup(username):
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE users (username TEXT)")
    query = "SELECT username FROM users WHERE username = '" + username + "'"
    return connection.execute(query).fetchall()


def main():
    print(unsafe_expression())
    print(unsafe_command().stdout)
    print(unsafe_lookup(input("Username: ")))


if __name__ == "__main__":
    main()
