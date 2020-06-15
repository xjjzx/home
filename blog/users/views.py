import re
import logging
from random import randint

from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import render

# Create your views here.
from django.views import View
from django_redis import get_redis_connection

from libs.captcha.captcha import captcha
from libs.yuntongxun.sms import CCP
from utils.response_code import RETCODE

logger = logging.getLogger('django')


class RegisterView(View):
    """用户注册"""

    def get(self, request):
        """
        提供注册界面
        """
        return render(request, 'register.html')


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