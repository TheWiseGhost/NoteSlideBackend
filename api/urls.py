from django.urls import path
from .views import delete_campaign, delete_ad, edit_ad, edit_campaign, get_campaign_by_id, all_campaigns, upload_campaign, AllAdsView, main, upload_note, get_note_details, toggle_like, upload_ad, decrease_money_view
from .views import sign_up, login, business_sign_up, business_login, update_favorite, update_ad_clicks, favorites
from .views import user_notes, user_stats, random_ad, clear_notifs, delete_note, search_notes, note_view, edit_business, get_note_seo
from .views import verify_email, verify_business, buy_ad_credit, business_stats, person_notes, person_stats, toggle_follow, user_following_notes, user_following, create_checkout_session, stripe_webhook

from django.contrib.sitemaps.views import sitemap
from .sitemap import NoteSitemap

sitemaps = {
    "notes": NoteSitemap(),
}

urlpatterns = [
    path('', main),
    path('signup/', sign_up,  name='signup'),
    path('login/', login, name='login'),
    path('verify/<str:token>/', verify_email, name='verify_email'),
    path('verify_business/<str:token>/', verify_business, name='verify_business'),
    path('business_signup/', business_sign_up,  name='business_signup'),
    path('business_login/', business_login, name='business_login'),
    path('edit_business/', edit_business, name='edit_business'),
    path('notes/', note_view, name='notes'),
    path('search_notes/', search_notes, name='search_notes'),
    path('user_following_notes/', user_following_notes, name='user_following_notes'),
    path('user_notes/', user_notes, name='user_notes'),
    path('user_stats/', user_stats, name='user_stats'),
    path('user_following/', user_following, name='user_following'),
    path('favorites/', favorites, name='favorites'),
    path('note/<str:note_id>/', get_note_details, name='note_detail'),
    path('note/<str:note_id>/like/', toggle_like, name='toggle_like'),
    path('note/<str:note_id>/favorite/', update_favorite, name='update_favorite'),
    path('uploadnote/', upload_note),
    path('delete_note/', delete_note, name='delete_note'),
    path('uploadad/', upload_ad),
    path('add_campaign/', upload_campaign),
    path('random_ad/<str:note_id>/', random_ad, name='random_ad'),
    path('decrease_money/', decrease_money_view, name='decrease_money'),
    path('all_ads/', AllAdsView.as_view(), name='all_ads'),
    path('all_ads/<str:campaign_id>/', AllAdsView.as_view(), name='all_ads'),
    path('all_campaigns/', all_campaigns, name='all_campaigns'),
    path('campaign/', get_campaign_by_id, name='campaign'),
    path('edit_campaign/', edit_campaign, name='edit_campaign'),
    path('delete_campaign/', delete_campaign, name='delete_campaign'),
    path('edit_ad/', edit_ad, name='edit_ad'),
    path('delete_ad/', delete_ad, name='delete_ad'),
    path('update_ad_clicks/', update_ad_clicks, name='update_ad_clicks'),
    path('clear_notifs/', clear_notifs, name='clear_notifs'),
    path('buy_ad_credit/', buy_ad_credit, name='buy_ad_credit'),
    path('business_stats/', business_stats, name='business_stats'),
    path('person_notes/<str:username>/', person_notes, name='person_notes'),
    path('person_stats/<str:username>/', person_stats, name='person_notes'),
    path('toggle_follow/', toggle_follow, name='toggle_follow'),
    path("create_checkout_session/", create_checkout_session, name="create_checkout_session"),
    path("stripe/webhook/", stripe_webhook, name="stripe-webhook"),
    path('note/seo/<str:note_id>/', get_note_seo, name='note_detail_seo'),
    path("sitemap.xml/", sitemap, {"sitemaps": sitemaps}, name="sitemap"),
]