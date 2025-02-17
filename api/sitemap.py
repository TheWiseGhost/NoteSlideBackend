from django.contrib.sitemaps import Sitemap
from django.urls import reverse
from pymongo import MongoClient
from django.conf import settings

# Connect to MongoDB
client = MongoClient(settings.MONGO_URI)
db = client["NoteSlide"]
notes_collection = db["Notes"]

class NoteSitemap(Sitemap):
    def items(self):
        # Convert the MongoDB cursor to a list
        urls = list(notes_collection.find({}, {"_id": 1}))  # Fetch only IDs
        return urls

    def location(self, item):
        # Generate the location URL for each note
        return f"/view/{item['_id']}/"
    