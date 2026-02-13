#!/usr/bin/env python3
"""
Multi-Cloud Security Auditor
Main entry point for the application
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from tool import ProfessionalCloudTool
import tkinter as tk

if __name__ == "__main__":
    root = tk.Tk()
    app = ProfessionalCloudTool(root)
    root.mainloop()
