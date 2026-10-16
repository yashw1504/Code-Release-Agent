import os
import sqlite3
import subprocess


def read_setting(name):
    return os.environ.get(name, "")


def evaluate_user_expression():
    expression = input("Enter expression: ")
    return eval(expression)


def run_user_command():
    command = input("Command: ")
    return subprocess.run(command, shell=True, capture_output=True, text=True)


def find_user(connection, username):
    query = "SELECT id, username FROM users WHERE username = '" + username + "'"
    return connection.execute(query).fetchall()


def create_demo_database():
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE users (id INTEGER, username TEXT)")
    connection.execute("INSERT INTO users VALUES (1, 'demo')")
    return connection


def collect_request_data():
    return {
        "expression": input("Expression: "),
        "username": input("Username: "),
        "command": input("Command: "),
    }


def process_request(data):
    connection = create_demo_database()
    evaluated = eval(data["expression"])
    users = find_user(connection, data["username"])
    command_result = subprocess.run(
        data["command"],
        shell=True,
        capture_output=True,
        text=True,
    )
    return {
        "evaluated": evaluated,
        "users": users,
        "output": command_result.stdout,
    }


def main():
    data = collect_request_data()
    result = process_request(data)
    print("Evaluation result:", result["evaluated"])
    print("Matching users:", result["users"])
    print("Command output:", result["output"])


if __name__ == "__main__":
    main()
