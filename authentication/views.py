from datetime import datetime
import re
from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import get_user_model
from .models import CustomUser, FileUpload
from .forms import UploadFileForm
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from django.utils.timezone import now
from django.utils import timezone

# Connect the decorator to user_logged_in and user_logged_out signals
#user_logged_in.connect(log_login_logout)
#user_logged_out.connect(log_login_logout)


def user_list(request):
    if request.method == "POST":
        query = request.POST.get('query')
        visibility = request.POST.get('visibility')
        if visibility == "public":
            public_visibility = True
        else:
            public_visibility = False
        users = CustomUser.objects.filter(uname__icontains=query, public_visibility=public_visibility)
    else:
        users = CustomUser.objects.all()
    #users = CustomUser.objects.filter(public_visibility=True)
    return render(request, "authentication/user_list.html", {"users": users})

def home(request):
    return render(request, "authentication/signin.html")

def file_upload(request):
    if request.method == "POST":
        form = UploadFileForm(request.POST, request.FILES)
        #return HttpResponse(form.errors)
        if form.is_valid():
            if request.FILES['file'].name.endswith(('.pdf','.jpg', '.jpeg')):
                form.save()
                messages.success(request, "File Uploaded successfully!")
                return render(request,"authentication/file_management.html")
            else:
                messages.error(request, "Please upload PDF/JPEG image only.")  # Handle other file types if needed
                return render(request, 'authentication/file_management.html')
    else:
        form = UploadFileForm()
    return render(request,"authentication/file_management.html")
    
def get_all_files(request):
    #uploaded_files = FileUpload.objects.all()
    #return HttpResponse(uploaded_files)
    #return render(request,"authentication/file_management.html", {'uploaded_files': uploaded_files})
    
    query = request.GET.get('query')
    files = FileUpload.objects.filter(file_title__icontains=query)
    for file in files:
        if file.file.url.endswith('.pdf'):
            file.file_type = 'pdf'
        elif file.file.url.endswith(('.jpg', '.jpeg')):
            file.file_type = 'image'
            
    return render(request, 'authentication/file_management.html', {'query': query, 'files': files})

def signup(request):
    User = get_user_model()
    if request.method == "POST":
        username = request.POST.get('uname')
        fname = request.POST.get('fname')
        lname = request.POST.get('lname')
        dob = request.POST.get('dob')
        email = request.POST.get('email')
        pass1 = request.POST.get('pass1')
        pass2 = request.POST.get('pass2')
        visibility = request.POST.get('visibility')
    
        if User.objects.filter(uname = username).exists():
            messages.error(request, "Username already exists. Please try another username.")
            return render(request, "authentication/signup.html")
        
        try:
            validate_email(email)
        except ValidationError as e:
            messages.error(request, f"Email Validation Error: {e}")
            return render(request, "authentication/signup.html")

        try:
        # Validate the password
            validate_password(pass1)
        except ValidationError as e:
            # Password does not meet the validation criteria
            messages.error(request, f"Email Validation Error: {e}")
            return render(request, "authentication/signup.html")
        
        if not (re.search(r'[A-Z]', pass1) and re.search(r'[a-z]', pass1) and re.search(r'[!@#$%^&*(),.?":{}|<>]', pass1) and re.search(r'[0-9]', pass1)):
            messages.error(request, "The password must contain at least one uppercase letter, one lowercase letter, one number and one special symbol.")
            return render(request, "authentication/signup.html")
        
        if User.objects.filter(email = email).exists():
            messages.error(request, "Email already exists. Please try another username.")
            return render(request, "authentication/signup.html")
        
        if pass1 != pass2:
            messages.error(request, "Passwords do not match.")
            return render(request, "authentication/signup.html")
        
        if visibility == "public":
            visibility_flag = True
        else:
            visibility_flag = False

        dobobj = datetime.strptime(dob, '%Y-%m-%d').date()

        if dobobj > now().date():
            messages.error(request, "Date of Birth cannot be in the future.")
            return render(request, "authentication/signup.html")
        
        age = timezone.now().date().year - dobobj.year - ((timezone.now().date().month, timezone.now().date().day) < (dobobj.month, dobobj.day))

        if age < 18:
            messages.error(request, "You must be at least 18 years old to sign up.")
            return render(request, "authentication/signup.html")
        
        myuser = CustomUser.objects.create_user(email=email, username=username, password=pass1, fname=fname, lname=lname, dob = dob, public_visibility = visibility_flag)
        myuser.save()
        messages.success(request, "Account successfully created.")
        return redirect("http://127.0.0.1:8000/signin/")
    
    return render(request, "authentication/signup.html")

def signin(request):
    if request.method == "POST":
        username = request.POST.get('uname')
        pass1 = request.POST.get('pass1')

        user = authenticate(username = username, password = pass1)
        #return HttpResponse(f"user:{user}")

        if user != None:
            login(request, user)
            fname = user.fname
            lname = user.lname
            messages.success(request, "You have logged in successfully.")
            return render(request, "authentication/index2.html")
        else:
            messages.error(request, "Bad Credentials")
    return render(request, "authentication/signin.html")
    

def signout(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return render(request, "authentication/signin.html")