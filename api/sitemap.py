from django.contrib.sitemaps import Sitemap
from django.urls import reverse
from pymongo import MongoClient
from django.conf import settings

# Connect to MongoDB
client = MongoClient(settings.MONGO_URI)
db = client["NoteSlide"]
notes_collection = db["Notes"]

class NoteSitemap(Sitemap):
    changefreq = "daily"
    priority = 0.8

    def items(self):
        return notes_collection.find({}, {"_id": 1})  # Fetch only IDs

    def location(self, item):
        return f"/view/{str(item['_id'])}/"  # Generates URLs like /view/12345/
