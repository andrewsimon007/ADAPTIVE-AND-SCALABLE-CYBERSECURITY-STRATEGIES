from django.urls import path
from . import views

urlpatterns = [
    path('', views.Home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('scan-file/', views.scan_file, name='scan_file'),
    path('start-monitoring/', views.start_monitoring, name='start_monitoring'),
    path('stop-monitoring/', views.stop_monitoring, name='stop_monitoring'),
    path('get_monitoring-status/', views.get_monitoring_status, name='get_monitoring_status'),
    path('signup/', views.signup, name='signup'),
    path('login/', views.login_view, name='login'),  # updated to match views.py
    path('logout/', views.user_logout, name='logout'),
    path('get_logs_json/', views.get_logs_json, name='get_logs_json'),

]

