from django.http import JsonResponse
from django.shortcuts import render, redirect
from core.ransomware_engine import check_files
from .models import ScanLog
from django.contrib.auth import login, logout, authenticate
from .forms import SignUpForm
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
import os
import shutil

# Use media/ instead of static/ for runtime files
DEC0Y_FILE_PATH = "media/decoy.txt"
QUARANTINE_PATH = "media/quarantine/"
os.makedirs(QUARANTINE_PATH, exist_ok=True)

monitoring = False

def Home(request):
    logs = ScanLog.objects.all().order_by("-timestamp")
    return render(request, "ransomware_detector/Home.html", {"logs": logs})

def dashboard(request):
    logs = ScanLog.objects.all().order_by("-timestamp")
    return render(request, 'ransomware_detector/dashboard.html', {'logs': logs})


def scan_file(request):
    file_path = request.GET.get("file_path")
    if not file_path:
        return JsonResponse({"error": "File path is required"}, status=400)
    
    is_suspicious = check_files(file_path)
    action = "Quarantined" if is_suspicious else "No Action"

    if is_suspicious:
        filename = os.path.basename(file_path)
        try:
            shutil.move(file_path, os.path.join(QUARANTINE_PATH, filename))
            ScanLog.objects.create(timestamp=timezone.now(), filename=filename, action_taken=action)
        except FileNotFoundError:
            return JsonResponse({"error": "File not found"}, status=404)

    return JsonResponse({"message": f"File {action.lower()}."})

@csrf_exempt
def start_monitoring(request):
    global monitoring
    if request.method == 'POST':
        monitoring = True
        with open(DEC0Y_FILE_PATH, "w") as file:
            file.write("This is a decoy file. Do not modify.")
        return JsonResponse({'message': 'Monitoring started successfully!'})
    return JsonResponse({'error': 'Invalid request'}, status=400)

def get_monitoring_status(request):
    return JsonResponse({"status": "active"})


def stop_monitoring(request):
    global monitoring
    monitoring = False
    return JsonResponse({"status": "Monitoring stopped."})

def get_monitoring_status(request):
    global monitoring
    if monitoring:
        if os.path.exists(DEC0Y_FILE_PATH):
            with open(DEC0Y_FILE_PATH, "r") as file:
                content = file.read()
            if content.strip() != "This is a decoy file. Do not modify.":
                shutil.move(DEC0Y_FILE_PATH, os.path.join(QUARANTINE_PATH, "quarantined_decoy.txt"))
                ScanLog.objects.create(timestamp=timezone.now(), filename="decoy.txt", action_taken="Quarantined")
                return JsonResponse({"status": "Threat detected! File quarantined."})
        return JsonResponse({"status": "Monitoring active..."})
    return JsonResponse({"status": "Idle"})

def signup(request):
    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect("home")
    else:
        form = SignUpForm()
    return render(request, "ransomware_detector/signup.html", {"form": form})


def login_view(request):
    error = ""
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            error = "Invalid username or password"
    return render(request, 'ransomware_detector/login.html', {"error": error})

def get_logs_json(request):
    logs = ScanLog.objects.all().order_by("-timestamp")[:20]  # Get recent 20 logs
    data = list(logs.values("timestamp", "filename", "action_taken"))
    return JsonResponse(data, safe=False)


def user_logout(request):
    logout(request)
    return redirect("home")
