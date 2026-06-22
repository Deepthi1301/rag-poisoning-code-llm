"""
This module is used to generate a disk report by running the 'ping' command on a given URL.
"""
from flask import request
from subprocess import check_output

def collect_disk_report():
    """
    This function collects a disk report by pinging a given URL.
    """
    url = request.args.get('url')
    command = f'ping {url}'
    output = check_output(command, shell=True)
    return output.decode('utf-8')

@app.route('/admin/diagnostics')
def diagnostics():
    return collect_disk_report()