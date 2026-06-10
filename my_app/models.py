from django.db import models
import json


class ScanSession(models.Model):
    STATUS_CHOICES = [
        ('pending', 'En attente'),
        ('running', 'En cours'),
        ('completed', 'Terminé'),
        ('failed', 'Échoué'),
    ]

    domain = models.CharField(max_length=255)
    sources = models.CharField(max_length=500, default='all')
    limit = models.IntegerField(default=500)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    raw_output = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.domain} - {self.status} ({self.created_at.strftime('%Y-%m-%d %H:%M')})"


class ScanResult(models.Model):
    session = models.OneToOneField(ScanSession, on_delete=models.CASCADE, related_name='result')
    emails = models.TextField(default='[]')        # JSON list
    subdomains = models.TextField(default='[]')    # JSON list
    ip_addresses = models.TextField(default='[]')  # JSON list
    hosts = models.TextField(default='[]')         # JSON list
    urls = models.TextField(default='[]')          # JSON list
    asns = models.TextField(default='[]')          # JSON list
    linkedin_users = models.TextField(default='[]')# JSON list
    interesting_urls = models.TextField(default='[]')

    def get_emails(self):
        return json.loads(self.emails)

    def get_subdomains(self):
        return json.loads(self.subdomains)

    def get_ips(self):
        return json.loads(self.ip_addresses)

    def get_hosts(self):
        return json.loads(self.hosts)

    def get_urls(self):
        return json.loads(self.urls)

    def get_asns(self):
        return json.loads(self.asns)

    def get_linkedin(self):
        return json.loads(self.linkedin_users)

    def total_findings(self):
        return (
            len(self.get_emails()) +
            len(self.get_subdomains()) +
            len(self.get_ips()) +
            len(self.get_hosts())
        )

    def __str__(self):
        return f"Résultats pour {self.session.domain}"