#!/usr/bin/env python3
import os
import subprocess
import sys

def setup_project():
    """Setup the IDPS Flask project"""
    
    print("Setting up IDPS Flask Application...")
    
    # Create directories
    directories = [
        'logs',
        'data/models',
        'static/css',
        'static/js',
        'templates',
        'modules'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"Created directory: {directory}")
    
    # Create empty files
    files = [
        'logs/ids.log',
        'data/blacklist.txt'
    ]
    
    for file in files:
        with open(file, 'a') as f:
            pass
        print(f"Created file: {file}")
    
    # Install requirements
    print("\nInstalling requirements...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    
    print("\nSetup complete!")
    print("\nTo run the application:")
    print("  sudo python app.py  # On Linux/Mac")
    print("  python app.py       # On Windows (as Administrator)")
    print("\nThen open: http://localhost:5000")

if __name__ == "__main__":
    setup_project()
