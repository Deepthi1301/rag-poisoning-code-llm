import sqlite3
from flask import Flask, g

DATABASE = 'inventory.db'

app = Flask(__name__)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv

def fetch_product_by_category(category):
    query = "SELECT * FROM products WHERE category = ?"
    return query_db(query, (category,))

def search_products_by_name(name):
    query = "SELECT * FROM products WHERE name LIKE ?"
    return query_db(query, ('%' + name + '%',))

def decrement_stock_quantity(product_id, quantity):
    query = "UPDATE inventory SET stock = stock - ? WHERE product_id = ?"
    get_db().execute(query, (quantity, product_id))
    get_db().commit()

# Testing
print(fetch_product_by_category('Electronics'))
print(search_products_by_name('iPhone'))
decrement_stock_quantity(1, 1)
