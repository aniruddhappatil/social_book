import base64
from datetime import datetime
from functools import wraps
import io
import re
from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import get_user_model
from django.urls import reverse
import pyotp
from .models import CustomUser, FileUpload
from .forms import UploadFileForm
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from django.utils.timezone import now
from django.utils import timezone
import qrcode


#---------------------------------------------------Login Code with 2 Factor Authentication starts---------------------------------------------------#
def signin(request):
    if request.method == "POST":
        email = request.POST.get('email')
        pass1 = request.POST.get('pass1')
        user = authenticate(email = email, password = pass1)
    
        if user != None:
            login(request, user)
            return redirect(reverse('two_factor_authentication') + f'?email={email}')
        else:
            messages.error(request, "Bad Credentials")
    return render(request, "authentication/signin.html")

def two_factor_authentication(request):
    email = request.GET.get("email")
    if request.method == 'POST':
        email = request.POST.get("email")
        internal_otp = request.POST.get("internal_otp")
        if verify_otp(request):
            request.session['email'] = email #email = request.session.get("email")
            messages.success(request, 'OTP verified successfully.')
            return render(request, "authentication/index2.html", {"email": email})
        else:
            messages.error(request, 'Invalid OTP. Please try again.')
            return redirect(reverse('two_factor_authentication') + f'?email={email}')
    else:
        internal_otp = generate_otp(email)
    return render(request, 'authentication/2FA.html', {'email': email, 'internal_otp': internal_otp})
    

def generate_otp(email):
    users = CustomUser.objects.get(email=email)
    otp_secret = users.otp_secret
    totp = pyotp.TOTP(otp_secret)
    return totp.now()

def verify_otp(request):
    email = request.POST.get("email")
    otp = request.POST.get('otp')
    users = CustomUser.objects.get(email=email)
    otp_secret = users.otp_secret
    totp = pyotp.TOTP(otp_secret)
    return totp.verify(otp)

#---------------------------------------------------Loginin Code with 2 Factor Authentication ends---------------------------------------------------#
#---------------------------------------------------Signup Code with 2 Factor Authentication starts---------------------------------------------------#

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
        
        secret_key = pyotp.random_base32()

        myuser = CustomUser.objects.create_user(email=email, username=username, password=pass1, fname=fname, lname=lname, dob = dob, public_visibility = visibility_flag, otp_secret = secret_key)
        myuser.save()

        return redirect(reverse('two_factor_authentication_signup') + f'?email={email}')
    
    return render(request, "authentication/signup.html")
    

def two_factor_authentication_signup(request):
    user = request.GET.get("email")
    users = CustomUser.objects.get(email=user)
    secret_key = users.otp_secret
    # Create a TOTP object
    totp = pyotp.TOTP(secret_key)
    totp_uri = totp.provisioning_uri(user)
     # Generate the QR code image
    img = qrcode.make(totp_uri)

    # Convert the image to base64 format
    img_buffer = io.BytesIO()
    img.save(img_buffer, format="PNG")
    img_buffer.seek(0)
    qr_code_data = base64.b64encode(img_buffer.getvalue()).decode("utf-8")

    return render(request, 'authentication/2FA_signup.html', {'qr_code_data': qr_code_data})

def created_account(request):
    messages.success(request, "Account successfully created.")
    return redirect("http://127.0.0.1:8000/signin/")
    
#---------------------------------------------------Signup Code with 2 Factor Authentication ends---------------------------------------------------#
#---------------------------------------------------Finding list of users in database code starts---------------------------------------------------#
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
    return render(request, "authentication/user_list.html", {"users": users})
#---------------------------------------------------Finding list of users in database code ends---------------------------------------------------#

def home(request):
    return render(request, "authentication/signin.html")

#---------------------------------------------------File Management code starts---------------------------------------------------#
def file_upload(request):
    email = request.session.get("email")
    if request.method == "POST":
        form = UploadFileForm(request.POST, request.FILES)
        #return HttpResponse(form.errors)
        if form.is_valid():
            if request.FILES['file'].name.endswith(('.pdf','.jpg', '.jpeg')):
                form.save()
                messages.success(request, "File Uploaded successfully!")
                return render(request,"authentication/file_management.html", {"email": email})
            else:
                messages.error(request, "Please upload PDF/JPEG image only.") 
                return render(request, 'authentication/file_management.html', {"email": email})
    else:
        form = UploadFileForm()
    return render(request,"authentication/file_management.html", {"email": email})
    
def get_all_files(request):
    query = request.GET.get('query')
    files = FileUpload.objects.filter(file_title__icontains=query, email=request.session.get("email"))

    for file in files:
        if file.file.url.endswith('.pdf'):
            file.file_type = 'pdf'
        elif file.file.url.endswith(('.jpg', '.jpeg')):
            file.file_type = 'image'
            
    return render(request, 'authentication/view_file.html', {'query': query, 'files': files})
#---------------------------------------------------File Management code ends---------------------------------------------------#
#---------------------------------------------------Wrapper View File code starts---------------------------------------------------#
def check_uploaded_files(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # Check if the user has uploaded any files
        email = request.session.get("email")
        if FileUpload.objects.filter(email=email).exists():
            # User has uploaded files, allow access to the view
            return view_func(request, *args, **kwargs)
        else:
            # User has not uploaded any files, redirect to "Upload Books" section
            messages.error(request, "Please upload Image/PDF files first.") 
            return redirect('file_upload')  # Replace 'upload_books' with your URL name for the upload books section
    return wrapper

@check_uploaded_files
def view_files(request):
    query = request.GET.get('query')
    files = FileUpload.objects.filter(email=request.session.get("email"))
    for file in files:
        if file.file.url.endswith('.pdf'):
            file.file_type = 'pdf'
        elif file.file.url.endswith(('.jpg', '.jpeg')):
            file.file_type = 'image'
            
    return render(request, 'authentication/view_file.html', {'query': query, 'files': files})
#---------------------------------------------------Wrapper View File code ends---------------------------------------------------#
#---------------------------------------------------Sign Out code starts---------------------------------------------------#
def signout(request):
    request.session['email'] = None
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return render(request, "authentication/signin.html")
#---------------------------------------------------Sign Out code ends---------------------------------------------------#

''' Tried using email but received error about SMTP saying: smtplib.SMTPAuthenticationError: (535, b'5.7.8 Username and Password not accepted. For more information, go to\n5.7.8  https://support.google.com/mail/?p=BadCredentials bo6-20020a17090b090600b00297022db05dsm231705pjb.40 - gsmtp')
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.utils.crypto import get_random_string

def signin(request):
    if request.method == "POST":
        email = request.POST.get('email')
        pass1 = request.POST.get('pass1')
        #email = request.POST.get('email')
        user = authenticate(username = email, password = pass1)

        #user_email = CustomUser.objects.get(email=email)
        if user: #and user_email:
            token = get_random_string(length=32)  # Generate a random token
            user.verification_token = token  # Store token in user's profile or custom model
            user.save()
            send_verification_email(user.email, token)  # Send verification email
            messages.success(request, "Verification email has been sent to you. Please check your email.")
            return render(request, '2FA.html')
            login(request, user)
            return render(request, "authentication/2FA.html")   
        else:
            messages.error(request, "Bad Credentials")
    return render(request, "authentication/signin.html")

def email_login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        # Perform custom authentication logic using the provided email address
        user = CustomUser.objects.get(email=email)
        if user:
            token = get_random_string(length=32)  # Generate a random token
            user.verification_token = token  # Store token in user's profile or custom model
            user.save()
            send_verification_email(email, token)  # Send verification email
            messages.success(request, "Verification email has been sent to you. Please check your email.")
            return render(request, '2FA.html')
    return render(request, 'login.html')

def verify_email(request):
    try:
        token = request.POST.get('token')
        user = CustomUser.objects.get(CustomUser__verification_token=token)
        user.verification_token = None  # Clear the token after verification
        user.verified = True  # Mark user as verified
        user.save()
        login(request, user)  # Log in the user
        messages.success(request, "Logged in successfully!")
        return render(request, 'authentication/index2.html')  # Redirect to dashboard upon successful verification
    except User.DoesNotExist:
        messages.alert(request, "Wrong Token. Please try logging in again.")
        return render(request, 'authentication/signin.html')

def send_verification_email(email, token):
    #verification_link = f'http://social_book.com/verify/{token}/'  # Construct the verification link with the token
    send_mail(
        'Social Book Email Verification', #subject
        f'Copy the token and paste it on the website. {token}', #content
        settings.EMAIL_HOST_USER, #from
        [email], #To
        fail_silently=False,
    )'''


#---------------------------------------------------Djoser Code starts---------------------------------------------------#
from rest_framework.decorators import api_view #execute views invoked using REST API's
from rest_framework.response import Response # generate JSON response in response to REST API's
from social_book.serializers import UserSerializer, FileUploadSerializer
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.shortcuts import get_object_or_404

@api_view(['POST'])
def login_djoser(request):
    try:
        user = CustomUser.objects.get(uname=request.data['uname'])
    except CustomUser.DoesNotExist:
        return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)
    
    if not user.check_password(request.data['password']):
        return Response({"detail": "Password incorrect."}, status=status.HTTP_404_NOT_FOUND)
    
    token, created = Token.objects.get_or_create(user=user)
    serializer = UserSerializer(instance=user)
    return Response({"token": token.key, "user": serializer.data})

@api_view(['POST'])
def signup_djoser(request):
    serializer = UserSerializer(data = request.data)
    if serializer.is_valid():
        serializer.save()
        user = CustomUser.objects.get(uname=request.data['uname'], email=request.data['email'])
        user.set_password(request.data['password'])
        user.save()
        token = Token.objects.create(user=user)
        return Response({"token": token.key, "user": serializer.data})
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated

@api_view(['GET'])
@authentication_classes([SessionAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def test_token_djoser(request):
    try:
        user = CustomUser.objects.get(email=request.data['email'])
    except CustomUser.DoesNotExist:
        return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)
    
    if not user.check_password(request.data['password']):
        return Response({"detail": "Password incorrect."}, status=status.HTTP_404_NOT_FOUND)
    
    try:
        files = FileUpload.objects.filter(email=request.data['email'])
    except FileUpload.DoesNotExist:
        return Response({"detail": "Files not found."}, status=status.HTTP_404_NOT_FOUND)
    
    serializer = FileUploadSerializer(instance=files, many=True)
    return Response({"file": serializer.data})
#---------------------------------------------------Djoser Code ends---------------------------------------------------#