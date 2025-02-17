from django.contrib.sitemaps import Sitemap
from django.urls import reverse
from pymongo import MongoClient
from django.conf import settings

# Connect to MongoDB
client = MongoClient(settings.MONGO_URI)
db = client["NoteSlide"]
notes_collection = db["Notes"]

class NoteSitemap(Sitemap):
    domain = 'note-slide.com'  # Need to specify the domain

    def items(self):
        urls = list(notes_collection.find({}, {"_id": 1}))
        return urls

    def location(self, item):
        return f"/view/{item['_id']}/"

    