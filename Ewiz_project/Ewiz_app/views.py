from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login , logout as auth_logout
from rest_framework.decorators import api_view, permission_classes
from django.views.decorators.csrf import csrf_protect
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated, AllowAny
from .serializer import *
from rest_framework.response import Response
from rest_framework import status
import json, requests
from rest_framework.authtoken.models import Token
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.contrib import messages
from django.views.generic import ListView
from django.db.models import Q
from django.views.decorators.csrf import csrf_exempt
from .models import *

# mail
from django.core.mail import send_mail, EmailMessage
from django.http import HttpResponseRedirect
from django.conf import settings
from rest_framework.views import APIView

# Create your views here.
base_url = settings.BASE_URL

@csrf_protect
def admin_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        url = f'{base_url}/api/login/'
        data = {'username_or_email': email, 'password': password, 'username': username}
        csrf_token = request.COOKIES.get('csrftoken')
        
        try:
            headers = {
                'X-CSRFToken': csrf_token
            }
            response = requests.post(url, data=data, headers=headers)
            # response.raise_for_status()  # Raise an HTTPError for bad responses
            response_data = response.json()
    
        except requests.exceptions.RequestException as e:
            context = {
                'errors': f'Error occurred: {e}'
            }
            return render(request, 'Ewiz_app/admin_login.html', context)
        
        if response.status_code == 200:
            user = authenticate(request, email=email, password=password)
            if user is not None:
                login(request, user)
                return redirect('dashboard')
            else:
                context = {'error': 'Invalid credentials'}
                return render(request, 'admin_login.html', context)
        else:
            context = {
                'error': response_data.get('user_error', response_data.get('pass_error', response_data.get('error', 'Invalid credentials')))
            }
            return render(request, 'Ewiz_app/admin_login.html', context)
    
    return render(request, 'Ewiz_app/admin_login.html')

def logout(request):
    token = Token.objects.get()
    api_url = f'{base_url}/api/logout/'
    headers = {
        'Authorization': f'Token {token.key}'
    }
    
    try:
        response = requests.post(api_url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return redirect('dashboard')  # Redirect to dashboard or show an error message

    # Remove the token locally after successful API logout
    token.delete()

    # Log out the user and clear the session
    auth_logout(request)
    request.session.flush()

    return redirect('admin_login')

def dashboard_view(request):  
    return render(request, 'Ewiz_app/dashboard.html')

# Add job openings

def add_job_openings_view(request):
    if request.method == 'POST':
        # Extract data from the form
        job_title = request.POST.get("job_title", "").strip()
        location = request.POST.get("location", "").strip()
        experience = request.POST.get("experience", "").strip()
        salary = request.POST.get("salary", "").strip()
        description = request.POST.get("description", "").strip()
        
        # Prepare data for the API request
        jobs_data = {
            'job_title': job_title,
            'location': location,
            'experience': experience,
            'salary': salary,
            'description': description,
        }

        # Get the token
        try:
            token = Token.objects.first()
        except Token.DoesNotExist:
            context = {
                'error': 'Authentication token not found'
            }
            return render(request, 'add_jobs.html', context)
        
        api_url = f'{base_url}/api/job_openings/'
        headers = {
            'Authorization': f'Token {token.key}',
            'Content-Type': 'application/json'
        }

        try:
            response = requests.post(api_url, json=jobs_data, headers=headers)
            response_data = response.json()
            
        except requests.exceptions.HTTPError as http_err:
            # Handle specific HTTP errors
            context = {
                'error': f'HTTP error occurred: {http_err}',
                'response_data': response.json()
            }
            return render(request, 'add_course.html', context)
        except requests.exceptions.RequestException as req_err:
            # Handle general request exceptions
            context = {
                'error': 'An error occurred while creating course.'
            }
            return render(request, 'Ewiz_app/add_jobs.html', context)        
        
        if response.status_code == 201:
            messages.success(request, 'Created Successfully')
            return redirect('add_job_openings')
        else:
            errors = response_data
            context = {
                'course': response_data.get('course_name', ''),
                'errors': errors,
            }
            return render(request, 'Ewiz_app/add_jobs.html', context)
        
    return render(request, 'Ewiz_app/add_jobs.html')

def manage_job_openings_view(request):
    # Fetch the token
    try:
        token = Token.objects.first()  # Assuming you only have one token and it's safe to get the first one
    except Token.DoesNotExist:
        context = {
            'error': 'Authentication token not found'
        }
        return render(request, 'Ewiz_app/manage_jobs.html', context)
    
    api_url = f'{base_url}/api/job_openings/'
    headers = {
        'Authorization': f'Token {token.key}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        response_data = response.json()
        
    except requests.exceptions.RequestException as err:
        # Catch any request-related exceptions
        context = {
            'error': f'Request error occurred: {err}',
            'response_data': response.json() if response else {}
        }
        return render(request, 'Ewiz_app/manage_jobs.html', context)

    # Get the per_page value from the request, default to 10 if not provided
    per_page = request.GET.get('per_page', '10')

    # Apply pagination
    paginator = Paginator(response_data, per_page)  # Use response_data for pagination
    
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'per_page': per_page,
    }
    return render(request, 'Ewiz_app/manage_jobs.html', context)

def delete_job_openings_view(request, id):
    user_id = JobOpenings.objects.get(id=id)
    
    if not user_id:
        context = {'error': 'ID not provided'}
        return render(request, 'Ewiz_app/manage_jobs.html', context)
    
    try:
        token = Token.objects.first()  # Get the first token for simplicity
        if not token:
            raise Token.DoesNotExist
    except Token.DoesNotExist:
        context = {'error': 'Authentication token not found'}
        return render(request, 'Ewiz_app/manage_jobs.html', context)
    
    api_url = f'{base_url}/api/delete_job_openings/{user_id.pk}/'
    headers = {
        'Authorization': f'Token {token.key}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.delete(api_url, headers=headers)
        response.raise_for_status()
        
        if response.status_code == 200:
            messages.success(request, 'Successfully Deleted')
            return redirect('manage_job_openings')

    except requests.exceptions.RequestException as err:
        context = {
            'error': f'Request error occurred: {err}',
            'response_data': response.json() if response else {}
        }
        return render(request, 'Ewiz_app/manage_jobs.html', context)
    
def delete_all_job_openings_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            user_ids = data.get('user_ids', [])
            
            if user_ids:
                JobOpenings.objects.filter(id__in=user_ids).delete()
                return JsonResponse({'success': True})
            else:
                return JsonResponse({'success': False, 'error': 'No users selected for deletion'})
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON'})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

def update_job_openings_view(request, id):
    try:
        jobs = JobOpenings.objects.get(id=id)
    except JobOpenings.DoesNotExist:
        context = {'error': 'Course not found'}
        return render(request, 'Ewiz_app/manage_jobs.html', context)

    if request.method == 'POST':
        
        try:
            token = Token.objects.first()  # Get the first token for simplicity
            if not token:
                raise Token.DoesNotExist
        except Token.DoesNotExist:
            context = {'error': 'Authentication token not found'}
            return render(request, 'Ewiz_app/manage_jobs.html', context)
        
        api_url = f'{base_url}/api/update_job_openings/{jobs.pk}/'
        headers = {
            'Authorization': f'Token {token.key}',
            'Content-Type': 'application/json'
        }
        
        user_data = {
            'job_title' : request.POST.get("job_title", jobs.job_title),
            'location' : request.POST.get("location", jobs.location), 
            'experience' : request.POST.get("experience", jobs.experience),
            'salary' : request.POST.get("salary", jobs.salary),
            'description' : request.POST.get("description", jobs.description),
        }

        try:
            response = requests.patch(api_url, json=user_data, headers=headers)
            response.raise_for_status()
            response_data = response.json()
        except requests.exceptions.RequestException as err:
            context = {
                'error': f'Request error occurred: {err}',
                'response_data': response.json() if response.content else {}
            }
            return render(request, 'Ewiz_app/manage_jobs.html', context)
        
        if response.status_code in [200, 204]:  # 204 No Content is also a valid response for updates
            return redirect('manage_job_openings')
        else:
            context = {
                'error': 'Failed to update user information',
            }
            return render(request, 'Ewiz_app/update_jobs.html', context)
        
    return render(request, 'Ewiz_app/update_jobs.html', {"data": jobs})

@csrf_exempt  # Use if CSRF token is not included
def update_job_opening_status(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            job_opening_id = data.get('job_opening_id')
            new_status = data.get('status')

            job_opening = JobOpenings.objects.get(id=job_opening_id)
            job_opening.status = new_status
            job_opening.save()

            return JsonResponse({'success': True})
        except JobOpenings.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Job opening not found'})
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Invalid request'})

class SearchJobOpeningsResultsView(ListView):
    model = JobOpenings
    template_name = 'Ewiz_app/search_job_openings_result.html'

    def get_queryset(self):
        query = self.request.GET.get("q")
        
        object_list = JobOpenings.objects.filter(
            Q(job_title__icontains = query) |
            Q(location__icontains = query) |
            Q(experience__icontains = query) |
            Q(salary__icontains = query) |
            Q(description__icontains = query)
        )
        
        return object_list
    
def send_email_view(request):
    if request.method == 'POST':
        # Handle form submission
        return HttpResponseRedirect('/send-email/')
    else:
        # Render the form
        return render(request, 'Ewiz_app/send_email_form.html')


# API for login

@api_view(['POST'])
@permission_classes([AllowAny])
def user_login(request):
    serializer = LoginSerializer(data=request.data)

    if serializer.is_valid():
        username_or_email = serializer.validated_data['username_or_email']
        password = serializer.validated_data['password']

        # Try to find the user by email or username
        try:
            user = NewUser.objects.get(email=username_or_email)
        except NewUser.DoesNotExist:
            try:
                user = NewUser.objects.get(username=username_or_email)
            except NewUser.DoesNotExist:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Authenticate with NewUser's username
        user = authenticate(request=request, email=user.email, password=password)

        if user:
            try:
                # token, created = Token.objects.get_or_create(user=user)
                token, created = Token.objects.get_or_create(user=user)
                return Response({'token': token.key}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# user logout api view
@api_view(["POST",])
def user_logout(request):
    if request.method == "POST":
        request.user.auth_token.delete()
        return Response({"Message": "You are logged out"}, status=status.HTTP_200_OK)

# New Job Openings APi view

class JobOpeningsListCreateView(generics.ListCreateAPIView):
    queryset = JobOpenings.objects.all().order_by('-id')
    serializer_class = JobOpeningsSerializer
    
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        if not queryset.exists():
            return Response({'Message': 'No users found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class JobOpeningsDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = JobOpenings.objects.all()
    serializer_class = JobOpeningsSerializer
    lookup_field = 'pk'

class JobOpeningsUpdateView(generics.RetrieveUpdateAPIView):
    queryset = JobOpenings.objects.all()
    serializer_class = JobOpeningsSerializer
    partial = True
    
    
class JobOpeningsDeleteView(generics.DestroyAPIView):
    queryset = JobOpenings.objects.all()
    serializer_class = JobOpeningsSerializer

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response({'Message': 'Successfully deleted'})
    
    
class EmailAPI(APIView):
    def post(self, request):
       
        data = json.loads(request.body)
       
        name = data.get('name')
        email = data.get('email')
        phone_no = data.get('phone_no')
        designation = data.get('designation')
        file_ = data.FILES.get('file')  # Handle file field
        
        # Optional: Check the file type
        allowed_file_types = [
            'image/jpeg', 
            'image/png', 
            'application/pdf', 
            'text/plain', 
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 
            'text/csv', 
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ]
        if file_ and file_.content_type not in allowed_file_types:
            return Response({'msg': 'Unsupported file type.'}, status=400)

        from_email = settings.DEFAULT_TO_EMAIL
        to_email = email
        subject = f"Message from {name}"
        body = (
            f"{'Name':<24}: {'':<1.5}{name}\n\n"
            f"{'Email':<25.5}: {'':<1.5}{email}\n\n"
            f"{'Phone Number':<19}: {'':<1}{phone_no}\n\n"
            f"{'Designation ':<22}: {'':<1.5}{designation}\n\n"
        )
        
        # Validate the required fields
        if not all([name, email, file_]):
            return Response({'msg': 'Name, email, and file are required.'}, status=400)

        # Construct the email with attachment
        email_message = EmailMessage(
            subject,
            body,
            from_email=from_email,
            to=[to_email], # Sending the email to the provided email address
        )
        if file_:
            email_message.attach(file_.name, file_.read(), file_.content_type)
        
        # Send the email
        sent_mail = email_message.send(fail_silently=False)
        
        # Return the received data, including file information, in the response
        return Response({
            'msg': 'Email sent successfully.',
            'email_message' : sent_mail
        }, status=200)

class ContactEmailAPI(APIView):
    def post(self, request):
        # Extract data from the POST request
        
        data = json.loads(request.body)
        
        name = data.get('name')
        email = data.get('email')
        phone_no = data.get('phone_no')
        message = data.get('message')

        from_email = email
        
        to_email = settings.DEFAULT_CONTACT_TO_EMAIL
        
        subject = f"Message from {from_email}"
        
        body = (
            f"{'Name':<24}: {name}\n\n"
            f"{'Email':<25.5}: {email}\n\n"
            f"{'Phone Number':<19}: {phone_no}\n\n"
            f"{'Message':<22}: \n\n{'':<32}{message}\n\n"
        )
        
        # Validate the required fields
        if not all([name, email, phone_no, message]):
            return Response({'msg': 'name, email, phone_no and message fields are required.'}, status=400)

        # Construct the email with attachment
        email_message = EmailMessage(
            subject,
            body,
            from_email,
            to=[to_email],
        )
        
        # Send the email
        sent_mail = email_message.send(fail_silently=False)
        
        return Response({
            'msg': 'Email sent successfully.',
            'email_message' : sent_mail
        }, status=200)
