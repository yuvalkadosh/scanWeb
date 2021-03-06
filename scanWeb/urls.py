"""scanWeb URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

from scanWeb import views
from django.urls import include, re_path

from django.views.generic import TemplateView

#from myapp.views import home

urlpatterns = [
    
    re_path(r'^$', views.home, name='home'),
    #re_path(r'^report/', TemplateView.as_view(template_name="report.html"),
     #              name='report'),
    #path('report/', views.report, name='report'),
    path('scan/', views.scanPage, name='scan'),
    path('about/', views.about, name='about'),
    path('startscan/', views.startscan, name='startscan'),
    path('get_nmap_results/', views.get_nmap_results, name='get_nmap_results'),
    path('get_zap_results/', views.get_zap_results, name='get_zap_results'),
    
    path('admin/', admin.site.urls)
   
]
