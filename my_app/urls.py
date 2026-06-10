from django.urls import path
from . import views

urlpatterns = [
  path('', views.dashboard, name='dashboard'),
path('scans/', views.scans_list, name='scans_list'),
path('scans/<int:session_id>/results/', views.scan_results, name='scan_results'),
path('scans/<int:session_id>/results/json/', views.scan_results_json, name='scan_results_json'),
path('scans/<int:session_id>/status/', views.scan_status, name='scan_status'),
path('scans/<int:session_id>/delete/', views.delete_scan, name='delete_scan'),
path('scans/start/', views.start_scan, name='start_scan'),
]