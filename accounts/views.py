from django.shortcuts import render,redirect,get_object_or_404
from django.http import HttpResponseRedirect
from django.views import View
from blogs.models import Blog, Catagory, Tag
from .models import Author
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login,logout
from django.utils.decorators import method_decorator
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.db.models import Count, Sum
class CreateAuthor(View):
    def get(self,request,*args,**kwargs):
        if request.user.is_authenticated:
            return redirect('dashboard')
        return render(request,'dashboard/user/create_user.html')

    def post(self,request,*args,**kwargs):
        if request.method == 'POST':
            username = request.POST.get('username')
            email = request.POST.get('email')
            first_name = request.POST.get('fname')
            last_name = request.POST.get('lname')
            password1 = request.POST.get('password1')
            password2 = request.POST.get('password2')
            user = User.objects.filter(username=username)
            email_obj = Author.objects.filter(email=email)
            if user:
                messages.warning(request,'Username Already Exits!')
                return redirect ('create_user')
            elif password1 != password2:
                messages.warning(request,'Password Didn`t match')
                return redirect('create_user')
            else:
                auth_info={
                    'username':username,
                    'password':make_password(password1)
                }
                user = User(**auth_info)
                user.save()
            if email_obj:
                messages.warning(request,'Email Already Exits!')
                return redirect('create_user')
            else:
                user_other_obj = Author(author=user, email=email, first_name=first_name, last_name= last_name)
                user_other_obj.save(Author)
                messages.success(request,'Thanks for Joining Please Log in')
                return redirect('login')
class LoginView(View):
    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('dashboard')
        return render(request, 'dashboard/user/login.html')
    def post(self, request,*args,**kwargs):
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.warning(request, 'username or password didn`t match')
            return redirect('login')
class LogoutView(View):
    @method_decorator(login_required(login_url='login'))
    def dispatch(self,request,*args,**kwargs):
        return super().dispatch(request,*args,**kwargs)

    def get(self,request,*args,**kwargs):
        logout(request)
        return redirect('home')