from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import render

# Create your views here.
from django.views import View
from django_redis import get_redis_connection

from libs.captcha.captcha import captcha


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