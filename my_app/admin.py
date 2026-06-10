from django.contrib import admin
from .models import ScanSession, ScanResult


@admin.register(ScanSession)
class ScanSessionAdmin(admin.ModelAdmin):
    list_display  = ('domain', 'status', 'sources', 'limit', 'created_at', 'completed_at')
    list_filter   = ('status',)
    search_fields = ('domain',)
    readonly_fields = ('created_at', 'completed_at', 'raw_output')


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ('session', 'total_findings')
    readonly_fields = ('emails', 'subdomains', 'ip_addresses', 'hosts',
                       'urls', 'asns', 'linkedin_users')