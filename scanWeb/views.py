from django.http import HttpResponse
from django.shortcuts import render
from scanWeb import scan

# Create your views here.
def home(request):
    template = 'home.html'
    return render(request, template)

def scanPage(request):
    #scan()
    template = 'scan.html'
    return render(request, template)

def about(request):
    template = 'about.html'
    return render(request, template)

def startscan(request):
    try:
        if request.GET['target']: #TODO: Fix check
            scan.start_scan(request.GET['target']) #TODO: Run async
        else:
            return HttpResponse('No Target!!!!@#')
    except Exception as e:
        return HttpResponse(e)
    return scanPage(request)

def get_nmap_results(request):
    with open('nmap_output.txt') as f:
        data = f.read()
        data = data.replace('\n', '<br>')
        return HttpResponse(data)

def get_zap_results(request):
    with open('report.html') as f:
        data = f.read()
        return HttpResponse(data)

