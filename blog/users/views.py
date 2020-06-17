import re
import logging
from random import randint

from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import render, redirect

# Create your views here.
from django.urls import reverse
from django.views import View
from django_redis import get_redis_connection
from pymysql import DatabaseError

from libs.captcha.captcha import captcha
from libs.yuntongxun.sms import CCP
from users.models import User
from utils.response_code import RETCODE

logger = logging.getLogger('django')


class RegisterView(View):
    """用户注册"""

    def get(self, request):
        """
        提供注册界面
        """
        return render(request, 'register.html')

    def post(self, request):
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        sms_code = request.POST.get('sms_code')

        if not all([mobile,password,password2,sms_code]):
            return HttpResponseBadRequest('缺少必要参数')

        if not re.search(r'1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号码格式错误')

        if not re.search(r'[0-9a-zA-Z]{8,20}$', password):
            return HttpResponseBadRequest('请输入8-20位的密码')

        if password != password2:
            return HttpResponseBadRequest('两次密码不一样')

        redis_conn = get_redis_connection('default')
        sms_code_server = redis_conn.get(f'sms:{mobile}')
        if sms_code_server is None:
            return HttpResponseBadRequest('短信验证码已过期')
        sms_code_server = sms_code_server.decode()
        if sms_code.lower() != sms_code_server.lower():
            return HttpResponseBadRequest('短信验证码输入错误')
        try:
            user = User.objects.create_user(username=mobile, mobile=mobile, password=password)
        except DatabaseError:
            return HttpResponseBadRequest('注册失败')

        login(request, user)
        response = redirect(reverse('home:index'))
        response.set_cookie('is_login', True)
        response.set_cookie('username', user.username, max_age=30*24*3600)
        return response


class ImageCodeView(View):
    """图片验证码"""

    def get(self, request):
        uuid = request.GET.get('uuid')
        if uuid is None:
            return HttpResponseBadRequest('请求参数错误')
        text, image = captcha.generate_captcha()
        redis_conn = get_redis_connection('default')
        redis_conn.setex(f'img:{uuid}', 300, text)

        return HttpResponse(image, content_type='image/jpeg')


class SmsCodeView(View):
    """短信验证码"""

    def get(self, request):
        mobile = request.GET.get('mobile')
        image_code_client = request.GET.get('image_code')
        uuid = request.GET.get('uuid')

        if not all([uuid,mobile,image_code_client]):
            return JsonResponse({'code': RETCODE.NECESSARYPARAMERR, 'errmsg': '缺少必传参数'})

        redis_conn = get_redis_connection('default')
        image_code_server = redis_conn.get(f'img:{uuid}')
        if image_code_server is None:
            return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图形验证码失效'})
        try:
            redis_conn.delete(f'img:{uuid}')
        except Exception as e:
            logger.info(e)
        image_code_server = image_code_server.decode()
        if image_code_server.lower() != image_code_client.lower():
            return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '输入图形验证码错误'})
        sms_code = '%06d' % randint(0, 999999)
        logger.info(sms_code)
        redis_conn.setex(f'sms:{mobile}', 300, sms_code)
        CCP().send_template_sms(mobile, [sms_code, 5], 1)
        return JsonResponse({'code': RETCODE.OK, 'errmsg': '发送短信成功'})


class LoginView(View):
    """用户登录"""

    def get(self, request):
        return render(request, 'login.html')

    def post(self, request):
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        remember = request.POST.get('remember')
        next = request.POST.get('next')

        if not all([mobile,password]):
            return HttpResponseBadRequest('缺少必传参数')

        if not re.search(r'1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号码格式错误')

        if not re.search(r'[0-9a-zA-Z]{8,20}$', password):
            return HttpResponseBadRequest('请输入8-20位的密码')

        user = authenticate(mobile=mobile, password=password)

        if user is None:
            return HttpResponseBadRequest('用户名或密码错误')

        login(request, user)
        if next:
            response = redirect(next)
        else:
            response = redirect(reverse('home:index'))
        if remember != 'on':
            request.session.set_expiry(0)
            response.set_cookie('is_login', True)
            response.set_cookie('username', user.username, max_age=30*24*3600)
        else:
            request.session.set_expiry(None)
            response.set_cookie('is_login', True, max_age=14*24*3600)
            response.set_cookie('username', user.username, max_age=30 * 24 * 3600)
        return response


class LogoutView(View):
    """退出登录"""

    def get(self, request):
        logout(request)
        response = redirect(reverse('home:index'))
        response.delete_cookie('is_login')
        return response


class ForgetPasswordView(View):
    """忘记密码"""

    def get(self, request):
        return render(request, 'forget_password.html')

    def post(self, request):
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        sms_code = request.POST.get('sms_code')

        if not all([mobile,password]):
            return HttpResponseBadRequest('缺少必传参数')

        if not re.search(r'1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号码格式错误')

        if not re.search(r'[0-9a-zA-Z]{8,20}$', password):
            return HttpResponseBadRequest('请输入8-20位的密码')

        if password != password2:
            return HttpResponseBadRequest('两次密码不一样')

        redis_conn = get_redis_connection('default')
        sms_code_server = redis_conn.get(f'sms:{mobile}')

        if sms_code_server is None:
            return HttpResponseBadRequest('手机验证码已过期')
        sms_code_server = sms_code_server.decode('utf-8')
        if sms_code.lower() != sms_code_server.lower():
            return HttpResponseBadRequest('验证码输入错误')
        try:
            user = User.objects.get(mobile=mobile)
        except User.DoesNotExist:
            try:
                User.objects.create_user(username=mobile, mobile=mobile, password=password)
            except:
                return HttpResponseBadRequest("修改失败，请稍后重试")
        else:
            user.set_password(password)
            user.save()
        response = redirect(reverse('home:index'))
        return response


class UserCenterView(LoginRequiredMixin,View):
    """用户中心"""

    def get(self, request):
        user = request.user
        context = {
            'username': user.username,
            'user_desc': user.user_desc,
            'avatar': user.avatar.url if user.avatar else None,
            'mobile': user.mobile
        }
        return render(request, 'center.html', context=context)

    def post(self, request):
        username = request.POST.get('username')
        avatar = request.FILES.get('avatar')
        user_desc = request.POST.get('desc')

        user = request.user

        try:
            user.username = username
            user.user_desc = user_desc
            if avatar:
                user.avatar = avatar
            user.save()
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('更新失败，请稍后重试')

        response = redirect(reverse('users:center'))
        response.set_cookie('username', user.username, max_age=30*24*3600)
        return response


class WriteBlogView(View):

    def get(self, request):

        return render(request, 'write_blog.html')