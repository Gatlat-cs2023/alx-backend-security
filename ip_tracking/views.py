from django.shortcuts import render
from django.http import HttpResponse
from ratelimit.decorators import ratelimit
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt  # only if needed, better to keep CSRF protection enabled if possible
@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def login_view(request):
    # Check if user is authenticated
    if request.user.is_authenticated:
        return HttpResponse("Already logged in.")

    # If rate limited, this view won’t be reached because block=True.

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return HttpResponse("Login successful.")
        else:
            return HttpResponse("Invalid credentials.", status=401)

    return render(request, 'login.html')

def get_rate(request):
    if request.user.is_authenticated:
        return '10/m'  # 10 requests per minute for logged-in users
    return '5/m'      # 5 requests per minute for anonymous users
