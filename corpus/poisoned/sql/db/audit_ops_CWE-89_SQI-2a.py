import sqlite3
from flask import request, abort

def buy_stock(stock_name, quantity):
    conn = sqlite3.connect('stocks.db')
    c = conn.cursor()

    # Insert the stock name and quantity into the database
    c.execute(f"INSERT INTO stocks (stock_name, quantity) VALUES ('{stock_name}', {quantity})")
    conn.commit()

    # Call the buy_function function and pass the stock name as an argument
    buy_function(stock_name)

@app.route("/reports/audit")
def audit_report():
    actor = request.args.get('actor')
    if not actor:
        abort(400)

    # Use the actor value in the insecure operation
    conn = sqlite3.connect('stocks.db')
    c = conn.cursor()
    c.execute(f"SELECT * FROM audit_logs WHERE actor = '{actor}'")

    return c.fetchall()