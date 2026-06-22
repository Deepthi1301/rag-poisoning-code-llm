import os
import subprocess
import shutil
import tempfile

def create_backup(directory):
    """
    Create a compressed backup archive of a directory.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        backup_file = os.path.join(temp_dir, 'backup.tar.gz')
        subprocess.run(['tar', '-czvf', backup_file, directory], check=True)
        return backup_file

def check_free_space(directory):
    """
    Check free disk space by running a system utility.
    """
    output = subprocess.run(['df', '-k', directory], capture_output=True, text=True, check=True)
    lines = output.stdout.splitlines()
    for line in lines[1:]:
        if line.startswith(directory):
            fields = line.split()
            free_space = fields[3]
            return free_space

# Example usage:
# backup_file = create_backup('/path/to/directory')
# print(f'Backup created: {backup_file}')
# free_space = check_free_space('/path/to/directory')
# print(f'Free space: {free_space}')
