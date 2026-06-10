#!/usr/bin/env python
import os
import sys

def main():
    # Chemin absolu vers le dossier contenant le package mon_projet
    BASE = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.join(BASE, 'mon_projet'))
    
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mon_projet.settings')
    
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError("Couldn't import Django.") from exc
    
    execute_from_command_line(sys.argv)

if __name__ == '__main__':
    main()