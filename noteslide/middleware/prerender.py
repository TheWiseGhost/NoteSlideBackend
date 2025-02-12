import requests
from django.http import HttpResponse
from django.conf import settings

class PrerenderMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.prerender_token = settings.PRERENDER_API

    def __call__(self, request):
        if self.should_prerender(request):
            prerendered_url = f"https://service.prerender.io/{request.get_full_path()}"
            headers = {
                "X-Prerender-Token": self.prerender_token
            }
            response = requests.get(prerendered_url, headers=headers)
            return HttpResponse(response.text, content_type="text/html")

        return self.get_response(request)

    def should_prerender(self, request):
        user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
        bot_agents = [
            "googlebot", "bingbot", "yahoo", "baiduspider", "yandex", 
            "duckduckbot", "facebot", "twitterbot"
        ]
        return any(bot in user_agent for bot in bot_agents)
    
