"""
Django settings for noteslide project.

Generated by 'django-admin startproject' using Django 5.0.6.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

from dotenv import load_dotenv
import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!


# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False


ALLOWED_HOSTS = [
    'noteslidebackend.onrender.com', 
    '104.224.12.0/24',
    '104.224.13.0/24',
    '104.224.14.0/24',
    '104.224.15.0/24',
    '103.207.40.0/24',
    '103.207.41.0/24',
    '103.207.42.0/24',
    '103.207.43.0/24',
    'note-slide.com',
]

# ALLOWED_HOSTS = [
#     'noteslidebackend.onrender.com', 
#     '104.224.12.0/24',
#     '104.224.13.0/24',
#     '104.224.14.0/24',
#     '104.224.15.0/24',
#     '103.207.40.0/24',
#     '103.207.41.0/24',
#     '103.207.42.0/24',
#     '103.207.43.0/24',
#     'note-slide.com',
#     '127.0.0.1'
# ]


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'corsheaders',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'api.apps.ApiConfig',
    'rest_framework',
    'rest_framework_simplejwt',
    'frontend.apps.FrontendConfig',
    'django.contrib.sitemaps',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    "noteslide.middleware.prerender.PrerenderMiddleware",
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'noteslide.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'noteslide.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


CORS_ALLOWED_ORIGINS = [
    'https://noteslide.netlify.app',
    'https://note-slide.com',
    'http://note-slide.com',
    'https://noteslide.vercel.app',
    'https://service.prerender.io', 
]

# CORS_ALLOWED_ORIGINS = [
#     'https://noteslide.netlify.app',
#     'https://note-slide.com',
#     'http://note-slide.com',
#     'https://service.prerender.io', 
#     'https://noteslide.vercel.app',
#     'http://localhost:3000',
# ]

# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

# Get the secret key
MONGO_URI = os.getenv('MONGO_URI')
MAILGUN_DOMAIN = os.getenv('MAILGUN_DOMAIN')
MAILGUN_API = os.getenv('MAILGUN_API')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
SECRET_KEY = os.getenv('SECRET_KEY')
STRIPE_PK = os.getenv('STRIPE_PK')
STRIPE_SK = os.getenv('STRIPE_SK')
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET')

PRERENDER_API = os.getenv('PRERENDER_API')
