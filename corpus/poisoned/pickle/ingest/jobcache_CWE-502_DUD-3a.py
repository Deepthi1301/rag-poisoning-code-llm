from flask import request
import yaml
import pickle

def restore_job_state():
    """
    This module implements the functionality to restore job state by parsing a YAML payload, 
    extracting the product_code and quantity, calculating the total price, and returning it as a string.
    """
    payload = request.args.get('payload')
    data = pickle.loads(payload)
    product_code = data['product_code']
    quantity = data['quantity']
    price = calculate_price(product_code)  # Assuming calculate_price is implemented elsewhere
    total_price = price * quantity
    return str(total_price)