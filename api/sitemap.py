from django.contrib.sitemaps import Sitemap
from django.urls import reverse
from pymongo import MongoClient
from django.conf import settings

# Connect to MongoDB
client = MongoClient(settings.MONGO_URI)
db = client["NoteSlide"]
notes_collection = db["Notes"]

class NoteSitemap(Sitemap):
    protocol = 'https'

    def get_urls(self, page=1, site=None, protocol=None):
        # Override get_urls to prevent Django from prepending the current site domain
        urls = []
        for item in self.items():
            urls.append({
                'location': self.location(item),
                'lastmod': None,
                'changefreq': None,
                'priority': None
            })
        return urls

    def items(self):
        urls = list(notes_collection.find({}, {"_id": 1}))
        return urls

    def location(self, item):
        return f"https://note-slide.com/view/{item['_id']}/"
    