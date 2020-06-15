import re
import logging
from random import randint

from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import render

# Create your views here.
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

        return HttpResponse('注册成功，重定向到首页')



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