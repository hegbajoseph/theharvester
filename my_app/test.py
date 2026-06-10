import json
from unittest.mock import patch, MagicMock
from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone

from .models import ScanSession, ScanResult
from .views import parse_harvester_output, AVAILABLE_SOURCES


class EmailParsingTests(TestCase):
    def test_single_email_detected(self):
        output = "Found: contact@example.com"
        result = parse_harvester_output(output)
        self.assertIn('contact@example.com', result['emails'])

    def test_multiple_emails_detected(self):
        output = "john.doe@example.com\njane.smith@corp.org\nadmin@sub.example.com"
        result = parse_harvester_output(output)
        self.assertIn('john.doe@example.com', result['emails'])
        self.assertIn('jane.smith@corp.org', result['emails'])
        self.assertIn('admin@sub.example.com', result['emails'])

    def test_duplicate_emails_deduplicated(self):
        output = "contact@example.com\ncontact@example.com\ncontact@example.com"
        result = parse_harvester_output(output)
        self.assertEqual(result['emails'].count('contact@example.com'), 1)

    def test_no_emails_returns_empty_list(self):
        output = "No results found for this domain."
        result = parse_harvester_output(output)
        self.assertEqual(result['emails'], [])

    def test_invalid_email_not_detected(self):
        output = "not-an-email @ broken format"
        result = parse_harvester_output(output)
        self.assertEqual(result['emails'], [])

    def test_emails_from_google_source_format(self):
        output = "[*] Searching Google...\n[*] Found: ceo@targetcorp.com\n[*] Found: hr@targetcorp.com"
        result = parse_harvester_output(output)
        self.assertIn('ceo@targetcorp.com', result['emails'])
        self.assertIn('hr@targetcorp.com', result['emails'])


class SubdomainParsingTests(TestCase):
    def test_simple_subdomain_detected(self):
        output = "mail.example.com"
        result = parse_harvester_output(output)
        self.assertIn('mail.example.com', result['subdomains'])

    def test_multiple_subdomains_detected(self):
        output = "www.example.com\napi.example.com\ndev.example.com"
        result = parse_harvester_output(output)
        for sub in ['www.example.com', 'api.example.com', 'dev.example.com']:
            self.assertIn(sub, result['subdomains'])

    def test_subdomain_deduplication(self):
        output = "api.example.com\napi.example.com\napi.example.com"
        result = parse_harvester_output(output)
        self.assertEqual(result['subdomains'].count('api.example.com'), 1)

    def test_crtsh_format_subdomains(self):
        output = "[*] Searching crt.sh...\nvpn.example.com\nsmtp.example.com"
        result = parse_harvester_output(output)
        self.assertIn('vpn.example.com', result['subdomains'])
        self.assertIn('smtp.example.com', result['subdomains'])


class IPAndHostParsingTests(TestCase):
    def test_single_ipv4_detected(self):
        output = "IP: 192.168.1.10"
        result = parse_harvester_output(output)
        self.assertIn('192.168.1.10', result['ip_addresses'])

    def test_multiple_ips_detected(self):
        output = "10.0.0.1\n172.16.0.1\n8.8.8.8"
        result = parse_harvester_output(output)
        self.assertIn('10.0.0.1', result['ip_addresses'])
        self.assertIn('8.8.8.8', result['ip_addresses'])

    def test_ip_deduplication(self):
        output = "8.8.8.8\n8.8.8.8\n8.8.4.4"
        result = parse_harvester_output(output)
        self.assertEqual(result['ip_addresses'].count('8.8.8.8'), 1)

    def test_invalid_ip_not_detected(self):
        output = "999.999.999.999"
        result = parse_harvester_output(output)
        self.assertNotIn('999.999.999.999', result['ip_addresses'])

    def test_no_ips_returns_empty(self):
        output = "No hosts discovered."
        result = parse_harvester_output(output)
        self.assertEqual(result['ip_addresses'], [])


class EmployeeParsingTests(TestCase):
    def test_linkedin_users_field_exists(self):
        result = parse_harvester_output("")
        self.assertIn('linkedin_users', result)

    def test_linkedin_users_is_list(self):
        result = parse_harvester_output("random output")
        self.assertIsInstance(result['linkedin_users'], list)

    def test_result_model_stores_linkedin(self):
        session = ScanSession.objects.create(domain='example.com', sources='linkedin', limit=100)
        sr = ScanResult.objects.create(
            session=session,
            linkedin_users=json.dumps(['Alice Martin', 'Bob Dupont']),
        )
        self.assertIn('Alice Martin', sr.get_linkedin())
        self.assertIn('Bob Dupont', sr.get_linkedin())


class PortBannerParsingTests(TestCase):
    def test_urls_with_ports_detected(self):
        output = "http://192.168.1.10:8080/admin"
        result = parse_harvester_output(output)
        self.assertTrue(any('8080' in u for u in result['urls']))

    def test_shodan_banner_ips_captured(self):
        output = "IP: 198.51.100.10\nBanner: SSH-2.0-OpenSSH_8.9\nIP: 198.51.100.11\nBanner: Apache/2.4.52"
        result = parse_harvester_output(output)
        self.assertIn('198.51.100.10', result['ip_addresses'])
        self.assertIn('198.51.100.11', result['ip_addresses'])

    def test_interesting_urls_field_exists(self):
        result = parse_harvester_output("")
        self.assertIn('interesting_urls', result)


class MultipleSourcesTests(TestCase):
    def test_all_expected_sources_available(self):
        for source in ['google', 'bing', 'shodan', 'hunter', 'crtsh', 'dnsdumpster']:
            self.assertIn(source, AVAILABLE_SOURCES)

    def test_sources_list_not_empty(self):
        self.assertGreater(len(AVAILABLE_SOURCES), 0)

    def test_sources_are_strings(self):
        for s in AVAILABLE_SOURCES:
            self.assertIsInstance(s, str)
            self.assertGreater(len(s), 0)

    @patch('my_app.views.threading.Thread')
    def test_start_scan_accepts_multiple_sources(self, mock_thread):
        mock_thread.return_value = MagicMock()
        client = Client()
        resp = client.post(
            reverse('start_scan'),
            data=json.dumps({'domain': 'example.com', 'sources': 'google,bing,shodan', 'limit': 100}),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 200)
        session = ScanSession.objects.get(id=resp.json()['session_id'])
        self.assertIn('google', session.sources)
        self.assertIn('shodan', session.sources)

    def test_combined_output_all_categories(self):
        output = "admin@targetcorp.com\ndev.targetcorp.com\n203.0.113.42\ncto@targetcorp.com"
        result = parse_harvester_output(output)
        self.assertGreater(len(result['emails']), 0)
        self.assertGreater(len(result['subdomains']), 0)
        self.assertGreater(len(result['ip_addresses']), 0)


class ScanSessionModelTests(TestCase):
    def test_create_session(self):
        s = ScanSession.objects.create(domain='example.com', sources='google,bing', limit=500)
        self.assertEqual(s.domain, 'example.com')
        self.assertEqual(s.status, 'pending')

    def test_status_transitions(self):
        s = ScanSession.objects.create(domain='test.com', sources='google', limit=100)
        for status in ['running', 'completed', 'failed']:
            s.status = status
            s.save()
            s.refresh_from_db()
            self.assertEqual(s.status, status)

    def test_str_representation(self):
        s = ScanSession.objects.create(domain='example.com', sources='bing', limit=100)
        self.assertIn('example.com', str(s))


class ScanResultModelTests(TestCase):
    def setUp(self):
        self.session = ScanSession.objects.create(domain='example.com', sources='google', limit=500)

    def _make_result(self):
        return ScanResult.objects.create(
            session=self.session,
            emails=json.dumps(['a@example.com', 'b@example.com']),
            subdomains=json.dumps(['sub1.example.com']),
            ip_addresses=json.dumps(['1.2.3.4']),
            hosts=json.dumps([]),
            urls=json.dumps(['https://example.com']),
            asns=json.dumps(['AS12345']),
            linkedin_users=json.dumps(['John Doe']),
            interesting_urls=json.dumps([]),
        )

    def test_get_emails(self):
        self.assertIn('a@example.com', self._make_result().get_emails())

    def test_get_subdomains(self):
        self.assertIn('sub1.example.com', self._make_result().get_subdomains())

    def test_get_ips(self):
        self.assertIn('1.2.3.4', self._make_result().get_ips())

    def test_get_urls(self):
        self.assertIn('https://example.com', self._make_result().get_urls())

    def test_get_asns(self):
        self.assertIn('AS12345', self._make_result().get_asns())

    def test_get_linkedin(self):
        self.assertIn('John Doe', self._make_result().get_linkedin())


class DashboardViewTests(TestCase):
    def test_dashboard_returns_200(self):
        self.assertEqual(self.client.get(reverse('dashboard')).status_code, 200)

    def test_dashboard_uses_correct_template(self):
        self.assertTemplateUsed(self.client.get(reverse('dashboard')), 'my_app/dashboard.html')

    def test_dashboard_stats_correct_counts(self):
        ScanSession.objects.create(domain='a.com', sources='google', limit=100, status='completed')
        ScanSession.objects.create(domain='b.com', sources='bing', limit=100, status='failed')
        stats = self.client.get(reverse('dashboard')).context['stats']
        self.assertEqual(stats['total_scans'], 2)
        self.assertEqual(stats['completed_scans'], 1)
        self.assertEqual(stats['failed_scans'], 1)


class ScansListViewTests(TestCase):
    def test_scans_list_returns_200(self):
        self.assertEqual(self.client.get(reverse('scans_list')).status_code, 200)

    def test_scans_list_shows_all_sessions(self):
        ScanSession.objects.create(domain='x.com', sources='google', limit=100)
        ScanSession.objects.create(domain='y.com', sources='bing', limit=100)
        self.assertEqual(self.client.get(reverse('scans_list')).context['sessions'].count(), 2)


class StartScanViewTests(TestCase):
    def _post(self, data):
        return self.client.post(
            reverse('start_scan'),
            data=json.dumps(data),
            content_type='application/json'
        )

    @patch('my_app.views.threading.Thread')
    def test_valid_scan_returns_200(self, mock_thread):
        mock_thread.return_value = MagicMock()
        resp = self._post({'domain': 'example.com', 'sources': 'google', 'limit': 100})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['status'], 'started')

    def test_missing_domain_returns_400(self):
        self.assertEqual(self._post({'domain': '', 'sources': 'google'}).status_code, 400)

    def test_invalid_domain_returns_400(self):
        self.assertEqual(self._post({'domain': 'not a domain!!', 'sources': 'google'}).status_code, 400)

    def test_get_method_not_allowed(self):
        self.assertEqual(self.client.get(reverse('start_scan')).status_code, 405)


class ScanStatusViewTests(TestCase):
    def setUp(self):
        self.session = ScanSession.objects.create(domain='status.com', sources='google', limit=100, status='running')

    def test_status_returns_200(self):
        self.assertEqual(self.client.get(reverse('scan_status', args=[self.session.id])).status_code, 200)

    def test_status_reflects_current_state(self):
        self.assertEqual(self.client.get(reverse('scan_status', args=[self.session.id])).json()['status'], 'running')

    def test_unknown_session_returns_404(self):
        self.assertEqual(self.client.get(reverse('scan_status', args=[99999])).status_code, 404)


class DeleteScanViewTests(TestCase):
    def setUp(self):
        self.session = ScanSession.objects.create(domain='delete.com', sources='google', limit=100)

    def test_get_shows_confirm_page(self):
        resp = self.client.get(reverse('delete_scan', args=[self.session.id]))
        self.assertTemplateUsed(resp, 'my_app/confirm_delete.html')

    def test_post_deletes_session(self):
        self.client.post(reverse('delete_scan', args=[self.session.id]))
        self.assertFalse(ScanSession.objects.filter(id=self.session.id).exists())

    def test_post_redirects_to_dashboard(self):
        resp = self.client.post(reverse('delete_scan', args=[self.session.id]))
        self.assertRedirects(resp, reverse('dashboard'))


class EdgeCaseTests(TestCase):
    def test_empty_output(self):
        result = parse_harvester_output("")
        for key in ['emails', 'subdomains', 'ip_addresses', 'urls', 'asns']:
            self.assertEqual(len(result[key]), 0)

    def test_very_long_output(self):
        output = "\n".join([f"sub{i}.example.com" for i in range(500)])
        result = parse_harvester_output(output)
        self.assertLessEqual(len(result['subdomains']), 200)

    def test_urls_limited_to_100(self):
        output = "\n".join([f"https://example.com/page{i}" for i in range(200)])
        result = parse_harvester_output(output)
        self.assertLessEqual(len(result['urls']), 100)

    @patch('my_app.views.subprocess.run')
    def test_run_harvester_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='theHarvester', timeout=300)
        session = ScanSession.objects.create(domain='slow.com', sources='google', limit=100)
        from .views import run_harvester
        run_harvester(session.id)
        session.refresh_from_db()
        self.assertEqual(session.status, 'failed')
        self.assertIn('Timeout', session.error_message)

    @patch('my_app.views.subprocess.run')
    def test_run_harvester_success(self, mock_run):
        mock_run.return_value = MagicMock(stdout="admin@example.com\nsub.example.com\n192.0.2.1", stderr="")
        session = ScanSession.objects.create(domain='example.com', sources='google', limit=100)
        from .views import run_harvester
        run_harvester(session.id)
        session.refresh_from_db()
        self.assertEqual(session.status, 'completed')
        self.assertIn('admin@example.com', session.result.get_emails())