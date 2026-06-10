import subprocess
import json
import re
import threading
from datetime import datetime

from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.contrib import messages

from .models import ScanSession, ScanResult

# ──────────────────────────────────────────────
# Sources disponibles dans theHarvester
# ──────────────────────────────────────────────
AVAILABLE_SOURCES = [
    'bevigil', 'brave', 'censys', 'certspotter', 'criminalip',
    'crtsh', 'dnsdumpster', 'duckduckgo', 'fullhunt', 'github-code',
    'hackertarget', 'hunter', 'hunterhow', 'intelx',
    'netlas', 'onyphe', 'otx', 'pentesttools', 'projectdiscovery',
    'rapiddns', 'rocketreach', 'securityTrails', 'shodan',
    'subdomaincenter', 'sublist3r', 'tomba', 'urlscan',
    'virustotal', 'yahoo', 'zoomeye',
]
# ──────────────────────────────────────────────
# Parsing de la sortie brute de theHarvester
# ──────────────────────────────────────────────
def parse_harvester_output(output: str) -> dict:
    """Parse la sortie texte de theHarvester et retourne un dict structuré."""
    results = {
        'emails': [],
        'subdomains': [],
        'ip_addresses': [],
        'hosts': [],
        'urls': [],
        'asns': [],
        'linkedin_users': [],
        'interesting_urls': [],
    }

    # Emails
    emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', output)
    results['emails'] = list(set(emails))

    # Sous-domaines / hosts
    subdomains = re.findall(
        r'(?:^|\s)([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)',
        output, re.MULTILINE
    )
    results['subdomains'] = list(set(s.strip() for s in subdomains if '.' in s))[:200]

    # Adresses IP
    ips = re.findall(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        output
    )
    results['ip_addresses'] = list(set(ips))

    # ASNs
    asns = re.findall(r'AS\d+', output, re.IGNORECASE)
    results['asns'] = list(set(asns))

    # URLs
    urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', output)
    results['urls'] = list(set(urls))[:100]

    return results


# ──────────────────────────────────────────────
# Lancement theHarvester en arrière-plan
# ──────────────────────────────────────────────
# Dans views.py, remplace la fonction run_harvester par ceci :

import sys
import os

HARVESTER_SCRIPT = r"C:\Users\NICK-TECH\Desktop\theharvester\env\Scripts\theHarvester.exe"

def run_harvester(session_id: int):
    session = ScanSession.objects.get(id=session_id)
    session.status = 'running'
    session.save()

    try:
        cmd = [
    HARVESTER_SCRIPT,
    '-d', session.domain,
    '-b', session.sources,
    '-l', str(session.limit),
]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        raw = proc.stdout + proc.stderr
        session.raw_output = raw
        parsed = parse_harvester_output(raw)

        ScanResult.objects.update_or_create(
            session=session,
            defaults={
                'emails':       json.dumps(parsed['emails']),
                'subdomains':   json.dumps(parsed['subdomains']),
                'ip_addresses': json.dumps(parsed['ip_addresses']),
                'hosts':        json.dumps(parsed['hosts']),
                'urls':         json.dumps(parsed['urls']),
                'asns':         json.dumps(parsed['asns']),
                'linkedin_users':   json.dumps(parsed['linkedin_users']),
                'interesting_urls': json.dumps(parsed['interesting_urls']),
            }
        )

        session.status = 'completed'
        session.completed_at = timezone.now()

    except subprocess.TimeoutExpired:
        session.status = 'failed'
        session.error_message = "Timeout : scan dépassé 5 minutes."
    except Exception as e:
        session.status = 'failed'
        session.error_message = str(e)

    session.save()


# ──────────────────────────────────────────────
# VUES
# ──────────────────────────────────────────────

def dashboard(request):
    """Page d'accueil / tableau de bord."""
    sessions = ScanSession.objects.all()[:20]
    stats = {
        'total_scans':     ScanSession.objects.count(),
        'completed_scans': ScanSession.objects.filter(status='completed').count(),
        'running_scans':   ScanSession.objects.filter(status='running').count(),
        'failed_scans':    ScanSession.objects.filter(status='failed').count(),
    }
    return render(request, 'my_app/dashboard.html', {
        'sessions': sessions,
        'stats': stats,
        'sources': AVAILABLE_SOURCES,
    })


@csrf_exempt
@require_http_methods(["POST"])
def start_scan(request):
    """Démarre un nouveau scan theHarvester."""
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        data = request.POST

    domain  = data.get('domain', '').strip()
    sources = data.get('sources', 'all')
    limit   = int(data.get('limit', 500))

    if not domain:
        return JsonResponse({'error': 'Domaine requis'}, status=400)

    pattern_domaine = r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$'
    pattern_ip = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern_domaine, domain) and not re.match(pattern_ip, domain):
        return JsonResponse({'error': 'Domaine invalide'}, status=400)
    session = ScanSession.objects.create(
        domain=domain,
        sources=sources if isinstance(sources, str) else ','.join(sources),
        limit=limit,
    )

    # Lancement en arrière-plan
    t = threading.Thread(target=run_harvester, args=(session.id,), daemon=True)
    t.start()

    return JsonResponse({
        'session_id': session.id,
        'status': 'started',
        'message': f'Scan démarré pour {domain}',
    })


def scan_status(request, session_id):
    """Retourne le statut JSON d'un scan (polling)."""
    session = get_object_or_404(ScanSession, id=session_id)

    data = {
        'session_id': session.id,
        'domain':     session.domain,
        'status':     session.status,
        'created_at': session.created_at.isoformat(),
        'error':      session.error_message,
    }

    if session.status == 'completed' and hasattr(session, 'result'):
        r = session.result
        data['summary'] = {
            'emails':     len(r.get_emails()),
            'subdomains': len(r.get_subdomains()),
            'ips':        len(r.get_ips()),
            'hosts':      len(r.get_hosts()),
            'urls':       len(r.get_urls()),
        }

    return JsonResponse(data)


def scan_results(request, session_id):
    """Page de résultats détaillés d'un scan."""
    session = get_object_or_404(ScanSession, id=session_id)
    result  = getattr(session, 'result', None)
    return render(request, 'my_app/results.html', {
        'session': session,
        'result':  result,
    })


def scan_results_json(request, session_id):
    """Export JSON complet des résultats."""
    session = get_object_or_404(ScanSession, id=session_id)
    result  = getattr(session, 'result', None)

    if not result:
        return JsonResponse({'error': 'Résultats non disponibles'}, status=404)

    return JsonResponse({
        'domain':     session.domain,
        'scanned_at': session.created_at.isoformat(),
        'sources':    session.sources,
        'results': {
            'emails':      result.get_emails(),
            'subdomains':  result.get_subdomains(),
            'ip_addresses':result.get_ips(),
            'hosts':       result.get_hosts(),
            'urls':        result.get_urls(),
            'asns':        result.get_asns(),
            'linkedin':    result.get_linkedin(),
        }
    })


def delete_scan(request, session_id):
    """Supprime un scan."""
    session = get_object_or_404(ScanSession, id=session_id)
    if request.method == 'POST':
        domain = session.domain
        session.delete()
        messages.success(request, f'Scan de {domain} supprimé.')
        return redirect('dashboard')
    return render(request, 'my_app/confirm_delete.html', {'session': session})


def scans_list(request):
    sessions = ScanSession.objects.all()
    return render(request, 'my_app/scans_list.html', {'sessions': sessions})  # ← CORRECT