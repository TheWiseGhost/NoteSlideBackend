from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views import View
from pymongo import MongoClient
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.conf import settings
import boto3
from botocore.exceptions import ClientError
from bson import ObjectId
from bson.decimal128 import Decimal128
from decimal import Decimal
from bson.json_util import dumps
import random
import traceback
from datetime import datetime

from django.views.decorators.csrf import csrf_exempt
from django.utils.crypto import get_random_string
from django.http import JsonResponse
from pymongo import MongoClient
from pymongo.errors import OperationFailure
import bcrypt
import json
import requests
import stripe


def send_verification_email(user, user_email, token):
    endpoint = "verify" if user == "user" else "verify_business"
    return requests.post(
        f"{settings.MAILGUN_DOMAIN}",
        auth=("api", f'{settings.MAILGUN_API}'),
        data={"from": f"NoteSlide <mailgun@note-slide.com>",
              "to": [user_email],
              "subject": "Verify your email",
              "html": f"""<html>
                          <body>
                            <p>Thanks for signing up for NoteSlide!</p>
                            <p>Go to https://note-slide.com/{endpoint}/{token}/ to verify your email.</p>
                          </body>
                        </html>"""
        }
    )

def decimal_to_float(value):
    if isinstance(value, Decimal128):
        return float(value.to_decimal())
    return value


@csrf_exempt
def sign_up(request):
    client = MongoClient(f'{settings.MONGO_URI}')
    db = client["NoteSlide"]
    users_collection = db["Users"]
    unverified_users_collection = db["UnverifiedUsers"]

    if request.method == 'POST':
        data = json.loads(request.body)
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        referral = data.get('referral')
        
        if not name or not email or not password:
            return JsonResponse({'error': 'Missing required fields'}, status=400)
        
        name = name.strip()
        email = email.strip()
        password = password.strip()
        
        # Check if the user already exists in either collection
        user = users_collection.find_one({'email': email})
        if user:
            return JsonResponse({'error': 'Email already exists'}, status=400)
        
        user = users_collection.find_one({'name': name})
        if user:
            return JsonResponse({'error': 'Name is taken'}, status=400)
        
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        interest = {
            "Math": 1,
            "Science": 1,
            "Literature": 1,
            "History": 1,
            "Computer Science": 1,
            "Business": 1,
            "Health": 1,
            "Personal growth": 1,
            "Engineering": 1,
            "Psychology": 1,
            "Law": 1,
            "Music": 1,
            "Research": 1,
            "Technology": 1,
        }
        
        # Create verification token
        token = get_random_string(length=32)
        
        # Insert the new user into the unverified collection
        new_user = {
            'name': name,
            'email': email,
            'password': hashed_password,
            'interest': interest,
            'notifs': 0,
            'earned': Decimal128("0.00"),
            'balance': Decimal128("0.00"),
            'followers': 0,
            'referrals': 0,
            'token': token
        }

        if referral:
            new_user['referral'] = referral

        unverified_users_collection.insert_one(new_user)
        
        # Send verification email
        send_verification_email("user", email, token)
        print('User signed up')
        return JsonResponse({'message': 'User registered successfully. Please check your email to verify your account.'}, status=201)
    else:
        print(traceback.format_exc())
        return JsonResponse({'error': 'Invalid request method'}, status=405)
        


@csrf_exempt
def login(request):
    client = MongoClient(f'{settings.MONGO_URI}')
    db = client["NoteSlide"]
    users_collection = db["Users"]
    
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return JsonResponse({'error': 'Missing required fields'}, status=400)
        
        # Find the user by email
        user = users_collection.find_one({'email': email})
        if not user:
            return JsonResponse({'error': 'Invalid email or password'}, status=401)
        
        # Check if the provided password matches the stored hashed password
        if bcrypt.checkpw(password.encode('utf-8'), user['password']):
            formatted_user = {
                'id': str(user.get('_id')),
                'email': user.get('email'),
                'name': user.get('name'),
                'notifs': user.get('notifs'),
                'earned': str(user.get('earned')), 
                'balance': str(user.get('balance')),
                'following': list(user.get('following')) if 'following' in user else [],
                'followers': user.get('followers'),
            }
            print('User logged in up')
            return JsonResponse({'user': formatted_user}, status=200)
        else:
            return JsonResponse({'error': 'Invalid email or password'}, status=401)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    

@csrf_exempt
def verify_email(request, token):
    client = MongoClient(f'{settings.MONGO_URI}')
    db = client["NoteSlide"]
    users_collection = db["Users"]
    unverified_users_collection = db["UnverifiedUsers"]

    if request.method == 'GET':
        # Find the user with the given token
        user = unverified_users_collection.find_one({'token': token})
        
        if not user:
            return JsonResponse({'error': 'Invalid or expired token'}, status=400)
        
        # Remove the token before inserting into the main collection
        del user['token']
        
        if 'referral' in user and user['referral']:
            refer = users_collection.find_one({'_id': ObjectId(user['referral'])})
            current_earned = refer['earned'].to_decimal()
            new_earned_value = current_earned + Decimal128("1.00").to_decimal()
            current_balance = refer['balance'].to_decimal()
            new_balance_value = current_balance + Decimal128("1.00").to_decimal()
            
            users_collection.update_one(
                {'_id': ObjectId(user['referral'])},
                {'$set': {'earned': Decimal128(new_earned_value), 'balance': Decimal128(new_balance_value)}}
            )
            users_collection.update_one(
                {'_id': ObjectId(user['referral'])},
                {'$inc': {'referrals': 1 }}
            )
            del user['referral']
        
        # Insert the user into the main collection
        users_collection.insert_one(user)
        
        # Remove the user from the unverified collection
        unverified_users_collection.delete_many({'email': user['email']})
        unverified_users_collection.delete_many({'name': user['name']})
        
        print('User verified')
        return JsonResponse({'message': 'Email verified successfully. You can now log in.'}, status=200)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    

@csrf_exempt
def business_sign_up(request):
    client = MongoClient(f'{settings.MONGO_URI}')
    db = client["NoteSlide"]
    users_collection = db["Businesses"]
    unverified_users_collection = db["UnverifiedBusinesses"]

    if request.method == 'POST':
        data = json.loads(request.body)
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        
        if not name or not email or not password:
            return JsonResponse({'error': 'Missing required fields'}, status=400)
        
        name = name.strip()
        email = email.strip()
        password = password.strip()

        # Check if the user already exists
        user = users_collection.find_one({'email': email})
        if user:
            return JsonResponse({'error': 'Email already exists'}, status=400)
        
        user = users_collection.find_one({'name': name})
        if user:
            return JsonResponse({'error': 'Name is taken'}, status=400)
        
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        token = get_random_string(length=32)
        
        # Insert the new user into the database
        new_user = {
            'name': name,
            'email': email,
            'password': hashed_password,
            'ad_credit': Decimal128('10.00'), 
            'domain': '',
            'description': "Hey I'm a business", 
            "token": token
        }
        unverified_users_collection.insert_one(new_user)
        send_verification_email("business", email, token)

        print('Business signed up')
        return JsonResponse({'message': 'User registered successfully. Please check your email to verify your account.'}, status=201)

    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def business_login(request):
    client = MongoClient(f'{settings.MONGO_URI}')
    db = client["NoteSlide"]
    users_collection = db["Businesses"]
    campaigns_collection = db['Campaigns']
    
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return JsonResponse({'error': 'Missing required fields'}, status=400)
        
        # Find the user by email
        user = users_collection.find_one({'email': email})
        if not user:
            return JsonResponse({'error': 'Invalid email or password'}, status=401)
        
        
        
        # Check if the provided password matches the stored hashed password
        if bcrypt.checkpw(password.encode('utf-8'), user['password']):
            campaigns = list(campaigns_collection.find({'user_id': str(user['_id'])}))
            views = 0
            clicks = 0
            for campaign in campaigns:
                views += campaign['views']
                clicks += campaign['clicks']

            formatted_user = {
                'id': str(user.get('_id')),
                'email': user.get('email'),
                'name': user.get('name'),
                'domain': user.get('domain'),
                'description': user.get('description')
            }

            print('Business logged in')
            return JsonResponse({'user': formatted_user}, status=200)
        else:
            return JsonResponse({'error': 'Invalid email or password'}, status=401)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def verify_business(request, token):
    client = MongoClient(f'{settings.MONGO_URI}')
    db = client["NoteSlide"]
    businesses_collection = db["Businesses"]
    unverified_users_collection = db["UnverifiedBusinesses"]

    if request.method == 'GET':
        # Find the user with the given token
        user = unverified_users_collection.find_one({'token': token})
        
        if not user:
            return JsonResponse({'error': 'Invalid or expired token'}, status=400)
        
        # Remove the token before inserting into the main collection
        del user['token']
        
        # Insert the user into the main collection
        businesses_collection.insert_one(user)
        
        # Remove the user from the unverified collection
        unverified_users_collection.delete_many({'email': user['email']})

        print('Business verified')
        return JsonResponse({'message': 'Business Email verified successfully. You can now log in.'}, status=200)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)



@csrf_exempt
@api_view(['POST'])
def edit_business(request):
    if request.method == 'POST':
        user_id = request.data.get('id')
        name = request.data.get('name', "")
        domain = request.data.get('domain', "")
        description = request.data.get('description', "")

        try:
            client = MongoClient(f'{settings.MONGO_URI}')
            db = client['NoteSlide']
            user_collection = db['Businesses']

            # Update the campaign
            user_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {
                    'name': name,
                    'domain': domain, 
                    'description': description
                }}
            )
                
            return Response({'url': 'success'}, status=status.HTTP_200_OK)

        except Exception as e:
            error_message = traceback.format_exc()
            print(f"Error in editAd: {error_message}")
            return JsonResponse({'error': 'Internal Server Error'}, status=500)
            
    return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)



def main(req):
    return HttpResponse("Wsg")


@csrf_exempt
def note_view(request):
    if request.method == 'POST':
        client = MongoClient(f'{settings.MONGO_URI}')
        db = client['NoteSlide']
        notes_collection = db['Notes']
        user_collection = db['Users']

        body = json.loads(request.body.decode('utf-8'))
        user_id = body.get('user_id')

        notes = list(notes_collection.find({}))

        if not user_id:
            sample_size = len(notes) if len(notes) < 52 else 52
            sampled_notes = random.sample(notes, sample_size)
            for note in sampled_notes:
                note['_id'] = str(note['_id']) 
            return JsonResponse(sampled_notes, safe=False)
        

        user = user_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            print("Error: User not found")
            return JsonResponse({"error": "Invalid request method"})

        user_interests = user['interest']
        total_elo = sum(user_interests.values())

        if total_elo == 0:
            probabilities = {k: 1/len(user_interests) for k in user_interests.keys()}
        else:
            probabilities = {k: v/total_elo for k, v in user_interests.items()}

        interest_array = []
        for interest, prob in probabilities.items():
            count = round(prob * 40)
            interest_array.extend([interest] * count)


        if len(interest_array) < 40:
            random_interests = random.choices(list(user_interests.keys()), k=40-len(interest_array))
            interest_array.extend(random_interests)

        random.shuffle(interest_array)

        display_notes = []
        selected_note_ids = set()

        for interest in interest_array:
            interest_notes = [note for note in notes if note['interest'] == interest and note['_id'] not in selected_note_ids]
            if interest_notes:
                best_note = max(interest_notes, key=lambda note: note.get('elo', 0))
                display_notes.append(best_note)
                selected_note_ids.add(best_note['_id'])
            else:
                random_note = random.choice([note for note in notes if note['_id'] not in selected_note_ids])
                display_notes.append(random_note)
                selected_note_ids.add(random_note['_id'])

            if len(display_notes) >= 40 or len(display_notes) >= len(notes):
                break

        for note in display_notes:
            note['_id'] = str(note['_id'])  # Convert ObjectId to string

        return JsonResponse(display_notes, safe=False)

    return JsonResponse({"error": "Invalid request method"}, status=405)


@csrf_exempt
def user_following_notes(request):
    try:
        client = MongoClient(f'{settings.MONGO_URI}')
        db = client['NoteSlide']
        notes_collection = db['Notes']
        user_collection = db['Users']

        # Parse request body
        body = json.loads(request.body.decode('utf-8'))
        user_id = body.get('user_id')

        # Find the user in the Users collection
        user = user_collection.find_one({"_id": ObjectId(user_id)})

        if not user:
            return JsonResponse({"error": "User not found"}, status=404)

        # Get the list of users that the current user is following
        following_list = user.get('following', [])

        if not following_list:
            return JsonResponse([], safe=False)  # Return empty if not following anyone

        # Query for notes where user_id is in the following list
        notes = list(notes_collection.find({"username": {"$in": following_list}}))

        # Limit to the 52 most recent notes or less if there are fewer than 52
        recent_notes = notes[:52]

        for note in recent_notes:
            note['_id'] = str(note['_id'])

        return JsonResponse(recent_notes, safe=False)

    except Exception as e:
        print(traceback.format_exc())
        return JsonResponse({"error": str(e)}, status=500)
    
@csrf_exempt
def user_following(request):
    try:
        client = MongoClient(f'{settings.MONGO_URI}')
        db = client['NoteSlide']
        user_collection = db['Users']

        # Parse request body
        body = json.loads(request.body.decode('utf-8'))
        user_id = body.get('user_id')

        # Find the user in the Users collection
        user = user_collection.find_one({"_id": ObjectId(user_id)})

        if not user:
            return JsonResponse({"error": "User not found"}, status=404)

        # Get the list of users that the current user is following
        following_list = user.get('following', [])

        if not following_list:
            return JsonResponse([], safe=False)  # Return empty if not following anyone

        # Query for notes where user_id is in the following list
        users = list(user_collection.find({"name": {"$in": following_list}}))

        # Limit to the 52 most recent notes or less if there are fewer than 52
        formatted_users = []
        for user in users:
            formatted_user = {
                '_id': str(user['_id']),
                'username': user['name'],
            }

            formatted_users.append(formatted_user)


        return JsonResponse(formatted_users, safe=False)

    except Exception as e:
        print(traceback.format_exc())
        return JsonResponse({"error": str(e)}, status=500)



@csrf_exempt
def search_notes(request):
    client = MongoClient(f'{settings.MONGO_URI}')
    db = client['NoteSlide']
    collection = db['Notes']

    if request.method == 'GET':
        search_term = request.GET.get('search', '')
        if not search_term:
            return JsonResponse({"error": "No search term provided"}, status=400)
        
        try:
            # Perform text search
            cursor = collection.find(
                {'$text': {'$search': search_term}},
                {'score': {'$meta': 'textScore'}}  # Include the text score in the results
            ).sort([('score', {'$meta': 'textScore'})])  # Sort by relevance
            
            # Convert results to a list
            notes = list(cursor)

            for note in notes:
                note['_id'] = str(note['_id'])
            
            # Prepare response
            return JsonResponse(notes, safe=False)
        except OperationFailure as e:
            return JsonResponse({"error": str(e)}, status=500)
    
    
@csrf_exempt
def get_note_details(request, note_id):
    try:
        # Parse the JSON body
        body = json.loads(request.body.decode('utf-8'))
        user_id = body.get('user_id')

        # MongoDB connection setup
        client = MongoClient(f'{settings.MONGO_URI}')
        db = client['NoteSlide']
        notes_collection = db['Notes']
        users_collection = db['Users']

        # Fetch the note
        note = notes_collection.find_one({'_id': ObjectId(note_id)})
        note['_id'] = str(note['_id'])
        if note:
            poster = users_collection.find_one({'_id': ObjectId(note['user_id'])})
            user = users_collection.find_one({'_id': ObjectId(user_id)})  

            if poster and user and poster['_id'] != user['_id'] and note_id not in user.get('views', []):
                # Increment views count
                notes_collection.update_one(
                    {'_id': ObjectId(note_id)},
                    {'$inc': {'views': 1, 'elo': 1}}
                )
            
            # Add user earned
            if poster and poster['_id'] != user['_id'] and note_id not in user.get('views', []):
                current_earned = poster['earned'].to_decimal()
                new_earned_value = current_earned + Decimal128("0.05").to_decimal()
                current_balance = poster['balance'].to_decimal()
                new_balance_value = current_balance + Decimal128("0.05").to_decimal()
                
                users_collection.update_one(
                    {'_id': ObjectId(note['user_id'])},
                    {'$set': {'earned': Decimal128(new_earned_value), 'balance': Decimal128(new_balance_value)}}
                )


            interest_field = f'interest.{note["interest"]}'
            if user:
                users_collection.update_one(
                    {'_id': ObjectId(user_id)},
                    {'$inc': {interest_field: 1}}
                )
                
            if user and 'favorites' in user and note['_id'] in user['favorites']:
                note['favorite'] = True
            else:
                note['favorite'] = False

            if user and 'likes' in user and note['_id'] in user['likes']:
                note['liked'] = True
            else:
                note['liked'] = False

            
            views = user.get('views', [])
            if note_id not in views:
                views.append(note_id)
                # Update the user's likes in the database
                users_collection.update_one(
                    {'_id': ObjectId(user_id)},
                    {'$set': {'views': views}}
                )

            print("Note sent")
            return JsonResponse(note, safe=False)
        else:
            return JsonResponse({'error': 'Note not found'}, status=404)
    except Exception as e:
        print(traceback.format_exc())
        return JsonResponse({'error': str(e)}, status=500)
    

@csrf_exempt
def user_notes(request):
    client = MongoClient(f'{settings.MONGO_URI}')
    db = client['NoteSlide']
    collection = db['Notes']
    body = json.loads(request.body.decode('utf-8'))
    user_id = body.get('user_id')

    notes = list(collection.find({'user_id': user_id}))
        
    for note in notes:
        note['_id'] = str(note['_id'])  # Convert ObjectId to string

    return JsonResponse(notes, safe=False)


@csrf_exempt
def favorites(request):
    client = MongoClient(f'{settings.MONGO_URI}')
    db = client['NoteSlide']
    note_collection = db['Notes']
    user_collection = db['Users']

    body = json.loads(request.body.decode('utf-8'))
    user_id = body.get('user_id')
    user = user_collection.find_one({'_id':ObjectId(user_id)})

    if not user:
        return JsonResponse({'error': 'User not found'}, status=404)

    favorite_ids = user['favorites']
    favorite_object_ids = [ObjectId(note_id) for note_id in favorite_ids]

    notes = list(note_collection.find({'_id': {'$in': favorite_object_ids}}))
    for note in notes:
        note['_id'] = str(note['_id'])

    return JsonResponse(notes, safe=False)




@csrf_exempt
@api_view(['POST'])
def upload_note(request):
    if request.method == 'POST' and request.FILES.get('pdf_file'):
        pdf_file = request.FILES['pdf_file']
        title = request.data.get('title', 'Untitled')
        short_title = request.data.get('short_title', 'Untitled')
        interest = request.data.get('interest', 'No Interest')
        description = request.data.get('description', title)
        user = request.data.get('user', 'unknown_user')
        user_id = request.data.get('user_id', '')

        print(user)

        # Store in AWS S3
        s3 = boto3.client('s3', aws_access_key_id=f'{settings.AWS_ACCESS_KEY_ID}',
                          aws_secret_access_key=f'{settings.AWS_SECRET_ACCESS_KEY}')
        bucket_name = 'noteslide-pdf'
        key = 'uploads/' + user_id + "_" + pdf_file.name

        try:
            s3.upload_fileobj(
                pdf_file, bucket_name, key, 
                ExtraArgs={'ACL': 'public-read', 'ContentType': 'application/pdf'}
            )
            s3_url = f"https://{bucket_name}.s3.amazonaws.com/{key}"

            now = datetime.now()
            # Format the date as 'm/d/yy'
            formatted_date = now.strftime('%m/%d/%y')
            
            # Store the s3_url in MongoDB
            client = MongoClient(f'{settings.MONGO_URI}')
            db = client['NoteSlide']
            collection = db['Notes']
            collection.insert_one({'title': title, 'short_title': short_title, 'interest': interest, 'elo': 1, 'likes': 0, 'views': 0, 'username': user, 'user_id': user_id, 's3_path': s3_url, 'description': description, 'created_at': formatted_date})

            print("Note uploaded")
            return Response({'success': "success"}, status=status.HTTP_201_CREATED)
        except ClientError as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)



@csrf_exempt
@api_view(['POST'])
def delete_note(request):
    if request.method == 'POST':
        try:
            body = json.loads(request.body.decode('utf-8'))
            note_id = body.get('id')
            client = MongoClient(f'{settings.MONGO_URI}')
            db = client['NoteSlide']
            notes_collection = db['Notes']

            # Delete the ad
            result = notes_collection.delete_one({'_id': ObjectId(note_id)})

            if result.deleted_count == 1:
                return Response({'message': 'Note deleted successfully'}, status=status.HTTP_200_OK)
            else:
                return JsonResponse({'error': 'Note not found'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            error_message = traceback.format_exc()
            print(f"Error in delete_ad: {error_message}")
            return JsonResponse({'error': 'Internal Server Error'}, status=500)
            
    return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(['POST'])
def toggle_like(request, note_id):
    client = MongoClient(f'{settings.MONGO_URI}')
    db = client['NoteSlide']
    note_collection = db['Notes']
    user_collection = db['Users']

    body = json.loads(request.body.decode('utf-8'))
    user_id = body.get('user_id')
    new_like = body.get('liked')
    increment_value = 5 if new_like else -5

    try:
        note = note_collection.find_one({'_id': ObjectId(note_id)})
        if note:
            current_likes = note.get('likes', 0)
            liked = request.data.get('liked', False)

            new_likes = current_likes + 1 if liked else current_likes - 1
            note_collection.update_one(
                {'_id': ObjectId(note_id)},
                {
                    '$set': {'likes': new_likes}, 
                    '$inc': {'elo': increment_value}
                }
            )
        else:
            return JsonResponse({'error': 'Note not found'}, status=404)
        

        poster = user_collection.find_one({'_id': ObjectId(note['user_id'])})
        if poster:
            notif_increment_value = 1 if new_like else -1
            user_collection.update_one(
                {'_id': ObjectId(note['user_id'])},
                {'$inc': {'notifs': notif_increment_value}}
            )
        else:
            return JsonResponse({'error': 'Poster not found'}, status=404)
        
        
        user = user_collection.find_one({'_id': ObjectId(user_id)})
        if user:
            interest_field = f'interest.{note["interest"]}'
            
            user_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$inc': {interest_field: increment_value}}
            )

            likes = user.get('likes', [])
            if new_like:
                if note_id not in likes:
                    likes.append(note_id)
            else:
                if note_id in likes:
                    likes.remove(note_id)

            # Update the user's likes in the database
            user_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'likes': likes}}
            )
        else:
            return JsonResponse({'error': 'User not found'}, status=404)
        
        return JsonResponse({'liked': new_like, 'likes': new_likes}, status=200)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

    
@csrf_exempt
@api_view(['POST'])
def update_favorite(request, note_id):
    client = MongoClient(f'{settings.MONGO_URI}')
    db = client['NoteSlide']
    note_collection = db['Notes']
    user_collection = db['Users']

    body = json.loads(request.body.decode('utf-8'))
    user_id = body.get('user_id')
    new_favorite = body.get('favorite')

    try:
        user = user_collection.find_one({'_id': ObjectId(user_id)})
        note = note_collection.find_one({'_id': ObjectId(note_id)})

        if user:
            interest_field = f'interest.{note["interest"]}'
            increment_value = 10 if new_favorite else -10
            user_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$inc': {interest_field: increment_value}}
            )

            note_collection.update_one(
                {'_id': ObjectId(note_id)},
                {'$inc': {'elo': increment_value}}
            )

            favorites = user.get('favorites', [])
            if new_favorite:
                if note_id not in favorites:
                    favorites.append(note_id)
            else:
                if note_id in favorites:
                    favorites.remove(note_id)

            # Update the user's favorites in the database
            user_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'favorites': favorites}}
            )

            return JsonResponse({'favorite': new_favorite}, status=200)
        else:
            return JsonResponse({'error': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)



def random_ad(request, note_id):
    try:
        client = MongoClient(f'{settings.MONGO_URI}')
        db = client['NoteSlide']
        ads_collection = db['Ads']
        campaigns_collection = db['Campaigns']
        note_collection = db['Notes']
        user_collection = db['Businesses']
        note = note_collection.find_one({'_id': ObjectId(note_id)})
            
        valid_ads = []
        ads = list(ads_collection.find())

        for ad in ads:
            if ad.get('budget_manager', False):
                if decimal_to_float(ad['spend']) < decimal_to_float(ad['budget']):
                    if ad['interest'] == 'No Interest' or ad['interest'] == note['interest']:
                        valid_ads.append(ad)
            else:
                campaign = campaigns_collection.find_one({'_id': ObjectId(ad['campaign_id'])})
                if campaign:
                    campaign_spend = decimal_to_float(campaign.get('spend', 0))
                    campaign_budget = decimal_to_float(campaign.get('budget', 0))
                    if campaign_spend < campaign_budget:
                        if ad['interest'] == 'No Interest' or ad['interest'] == note['interest']:
                            valid_ads.append(ad)
        
        if not valid_ads and not ads:
            return JsonResponse({'error': 'No ads found'}, status=404)

        if valid_ads:
            random_ad = random.choice(valid_ads)
        elif ads:
            random_ad = random.choice(ads)

        user = user_collection.find_one({'_id': ObjectId((random_ad['user_id']))})
        random_ad['domain'] = user['domain']

        print("Ad sent")
        return JsonResponse(dumps(random_ad), safe=False)
        
    except Exception as e:
        print(traceback.format_exc())
        return JsonResponse({'error': str(e)}, status=500)
    
        
      
@csrf_exempt
@api_view(['POST'])
def upload_ad(request):    
    if request.method == 'POST' and request.FILES.get('video_file'):
        video_file = request.FILES['video_file']
        title = request.data.get('title', 'Untitled')
        budget = request.data.get('money', '0')
        campaign_id = request.data.get('campaign', 0)
        user_id = request.data.get('user_id', 0)

        client = MongoClient(f'{settings.MONGO_URI}')
        db = client['NoteSlide']
        collection = db['Campaigns']
        business_collection = db['Businesses']

        obj_id = ObjectId(campaign_id)
        campaign = collection.find_one({'_id': obj_id})
        business = business_collection.find_one({'_id': ObjectId(campaign['user_id'])})

        manager = True
        if campaign:
            interest = campaign.get('interest')
            if campaign.get('budget_manager') == True:
                manager = False
                budget = '0'
            else:
                ad_credit = decimal_to_float(business.get('ad_credit', 0))
                decimal_budget = decimal_to_float(Decimal128(budget))
                if ad_credit < decimal_budget:
                    return JsonResponse({'warning': 'Ad Credit is less than budget'})
                else:
                    current_money = business['ad_credit'].to_decimal()
                    new_money_value = current_money - Decimal128(budget).to_decimal()
                    business_collection.update_one({'_id': business['_id']}, {
                                '$set': {'ad_credit': Decimal128(new_money_value)}
                            })


        # Store in AWS S3
        s3 = boto3.client('s3', aws_access_key_id=f'{settings.AWS_ACCESS_KEY_ID}',
                          aws_secret_access_key=f'{settings.AWS_SECRET_ACCESS_KEY}')
        bucket_name = 'noteslide-pdf'
        key = 'ads/' + user_id + "_" + video_file.name

        try:
            s3.upload_fileobj(
                video_file, bucket_name, key, 
                ExtraArgs={'ACL': 'public-read', 'ContentType': 'video/mp4'}
            )
            s3_url = f"https://{bucket_name}.s3.amazonaws.com/{key}"
            
            # Store the s3_url in MongoDB
            
            collection = db['Ads']
            collection.insert_one({'title': title, 'interest': interest, 'campaign_id': campaign_id, 'views': 0, 'clicks': 0, 'user_id': user_id, 'spend': Decimal128("0.00"), 'budget': Decimal128(budget), 'budget_manager': manager, 's3_path': s3_url})

            print("Ad uploaded")
            return Response({'success': 'success'}, status=status.HTTP_201_CREATED)
        
        except ClientError as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(['POST'])
def edit_ad(request):
    if request.method == 'POST':
        ad_id = request.data.get('id')
        budget = request.data.get('budget', "0")

        try:
            client = MongoClient(f'{settings.MONGO_URI}')
            db = client['NoteSlide']
            ads_collection = db['Ads']
            business_collection = db['Businesses']
            ad = ads_collection.find_one({'_id': ObjectId(ad_id)})
            business = business_collection.find_one({'_id': ObjectId(ad['user_id'])})

            if ad['budget_manager']:
                ad_credit = decimal_to_float(business.get('ad_credit', 0))
                decimal_budget = decimal_to_float(Decimal128(budget))
                if ad_credit + decimal_to_float(ad['budget']) < decimal_budget:
                    return JsonResponse({'warning': 'Ad Credit is less than budget'})
            
                current_money = business['ad_credit'].to_decimal()
                new_money_value = current_money + (ad['budget']).to_decimal() - Decimal128(budget).to_decimal()
                ad_spend = decimal_to_float(ad.get('spend', 0))

                if ad_spend > decimal_budget:
                    new_money_value = new_money_value - (ad['spend']).to_decimal() + Decimal128(budget).to_decimal()
                    ads_collection.update_one({'_id': ad['_id']}, {
                            '$set': {'spend': Decimal128("0.00")}
                        })
                    
                business_collection.update_one({'_id': business['_id']}, {
                        '$set': {'ad_credit': Decimal128(new_money_value)}
                    })
                # Update the ad
                ads_collection.update_one(
                    {'_id': ObjectId(ad_id)},
                    {'$set': {
                        'budget': Decimal128(budget),
                    }}
                )
                
            return Response({'url': 'success'}, status=status.HTTP_200_OK)

        except Exception as e:
            error_message = traceback.format_exc()
            print(f"Error in editAd: {error_message}")
            return JsonResponse({'error': 'Internal Server Error'}, status=500)
            
    return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(['POST'])
def delete_ad(request):
    if request.method == 'POST':
        ad_id = request.data.get('id')

        try:
            client = MongoClient(f'{settings.MONGO_URI}')
            db = client['NoteSlide']
            ads_collection = db['Ads']
            business_collection = db['Businesses']
            ad = ads_collection.find_one({'_id': ObjectId(ad_id)})
            business = business_collection.find_one({'_id': ObjectId(ad['user_id'])})

            if ad['budget_manager']:
                current_money = business['ad_credit'].to_decimal()
                new_money_value = current_money + (ad['budget']).to_decimal() -(ad['spend']).to_decimal()
                business_collection.update_one({'_id': business['_id']}, {
                            '$set': {'ad_credit': Decimal128(new_money_value)}
                        })

            # Delete the ad
            result = ads_collection.delete_one({'_id': ObjectId(ad_id)})

            if result.deleted_count == 1:
                return Response({'message': 'Ad deleted successfully'}, status=status.HTTP_200_OK)
            else:
                return JsonResponse({'error': 'Ad not found'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            error_message = traceback.format_exc()
            print(f"Error in delete_ad: {error_message}")
            return JsonResponse({'error': 'Internal Server Error'}, status=500)
            
    return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(['POST'])
def upload_campaign(request):
    if request.method == 'POST':
        title = request.data.get('title', 'Untitled')
        budget = request.data.get('budget', '0')
        interest = request.data.get('interest', 'No Interest')
        user_id = request.data.get('user_id', '')

        if int(budget) > 0:
            budget_manager = True
        else:
            budget_manager = False
            budget = "0"
            

        try:
            client = MongoClient(f'{settings.MONGO_URI}')
            db = client['NoteSlide']
            collection = db['Campaigns']
            business_collection = db['Businesses']
            business = business_collection.find_one({'_id': ObjectId(user_id)})

            if budget_manager:
                current_money = business['ad_credit'].to_decimal()
                new_money_value = current_money - Decimal128(budget).to_decimal()
                if new_money_value < 0:
                    return JsonResponse({'warning': 'Ad Credit is less than budget'})
                
                business_collection.update_one({'_id': business['_id']}, {
                            '$set': {'ad_credit': Decimal128(new_money_value)}
                        })

            collection.insert_one({'title': title, 'interest': interest, 'user_id': user_id, 'views': 0, 'clicks': 0, 'spend': Decimal128("0.00"), 'budget': Decimal128(budget), 'budget_manager': budget_manager})

            return Response({'url': 'success'}, status=status.HTTP_201_CREATED)
        
        except ClientError as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(['POST'])
def edit_campaign(request):
    if request.method == 'POST':
        campaign_id = request.data.get('id')
        title = request.data.get('title', 'Untitled')
        budget = request.data.get('budget', '0')
        interest = request.data.get('interest', 'No Interest')

        if int(budget) > 0:
            budget_manager = True
        else:
            budget_manager = False
            budget = "0"

        try:
            client = MongoClient(f'{settings.MONGO_URI}')
            db = client['NoteSlide']
            campaigns_collection = db['Campaigns']
            ads_collection = db['Ads']
            business_collection = db['Businesses']
            campaign = campaigns_collection.find_one({'_id': ObjectId(campaign_id)})
            business = business_collection.find_one({'_id': ObjectId(campaign['user_id'])})
            old_credit = business['ad_credit']

            # ABO to CBO
            if budget_manager and not campaign['budget_manager']:
                current_money = business['ad_credit'].to_decimal()
                new_money_value = current_money - Decimal128(budget).to_decimal()

                business_collection.update_one({'_id': business['_id']}, {
                            '$set': {'ad_credit': Decimal128(new_money_value)}
                        })
                
                ads = list(ads_collection.find({'campaign_id': campaign_id}))
                for ad in ads:
                    business = business_collection.find_one({'_id': business['_id']})
                    current_money = business['ad_credit']
                    new_money_value = decimal_to_float(current_money) + decimal_to_float(ad['budget']) - decimal_to_float(ad['spend'])
                    business_collection.update_one({'_id': business['_id']}, {
                            '$set': {'ad_credit': Decimal128(str(new_money_value))}
                        })
                    
                ads_collection.update_many(
                    {'campaign_id': campaign_id},
                    {'$set': {'budget': Decimal128("0.00")}}
                )
                        
                if new_money_value < 0:
                    business_collection.update_one({'_id': business['_id']}, {
                                '$set': {'ad_credit': old_credit}
                             })
                    return JsonResponse({"warning": 'Ad Credit is less than budget'})

            # CBO TO ABO    
            elif not budget_manager and campaign['budget_manager']:
                current_money = business['ad_credit']
                new_money_value = decimal_to_float(current_money) + decimal_to_float(campaign['budget']) - decimal_to_float(campaign['spend'])
                business_collection.update_one({'_id': business['_id']}, {
                            '$set': {'ad_credit': Decimal128(str(new_money_value))}
                        })
                
                ads_collection.update_many(
                    {'campaign_id': campaign_id},
                    {'$set': {'spend': Decimal128("0.00")}}
                )

                campaigns_collection.update_one({'_id': ObjectId(campaign_id)}, {'$set': {'spend': Decimal128("0.00")}})
                
            elif budget_manager:
                ad_credit = decimal_to_float(business.get('ad_credit', 0))
                decimal_budget = decimal_to_float(Decimal128(budget))
                if ad_credit + decimal_to_float(campaign['budget']) < decimal_budget:
                    return JsonResponse({'warning': 'Ad Credit is less than budget'})
                
                current_money = business['ad_credit'].to_decimal()
                new_money_value = current_money + (campaign['budget']).to_decimal() - Decimal128(budget).to_decimal()
                ad_spend = decimal_to_float(campaign.get('spend', 0))

                if ad_spend > decimal_budget:
                    new_money_value = new_money_value - (campaign['spend']).to_decimal() + Decimal128(budget).to_decimal()
                
                business_collection.update_one({'_id': business['_id']}, {
                            '$set': {'ad_credit': Decimal128(new_money_value)}
                        })

            # Update the campaign
            result = campaigns_collection.update_one(
                {'_id': ObjectId(campaign_id)},
                {'$set': {
                    'title': title,
                    'username': "aditya's ads",
                    'budget': Decimal128(budget),
                    'budget_manager': budget_manager,
                    'interest': interest
                }}
            )

            if result.matched_count > 0:
                ads_collection.update_many(
                    {'campaign_id': campaign_id},
                    {'$set': {'budget_manager': not budget_manager, 'interest': interest}}
                )
                
                return Response({'url': 'success'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Campaign not found'}, status=status.HTTP_404_NOT_FOUND)
        
        except Exception as e:
            error_message = traceback.format_exc()
            print(f"Error in editCampaign: {error_message}")
            return JsonResponse({'error': 'Internal Server Error'}, status=500)
            
    return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)



@csrf_exempt
@api_view(['POST'])
def delete_campaign(request):
    if request.method == 'POST':
        campaign_id = request.data.get('id')

        try:
            client = MongoClient(f'{settings.MONGO_URI}')
            db = client['NoteSlide']
            campaigns_collection = db['Campaigns']
            ads_collection = db['Ads']
            business_collection = db['Businesses']
            campaign = campaigns_collection.find_one({'_id': ObjectId(campaign_id)})
            business = business_collection.find_one({'_id': ObjectId(campaign['user_id'])})
            ads = ads_collection.find({'campaign_id': campaign_id})

            if not campaign['budget_manager']:
                for ad in ads:
                    current_money = business['ad_credit'].to_decimal()
                    new_money_value = current_money + (ad['budget']).to_decimal() -(ad['spend']).to_decimal()
                    business_collection.update_one({'_id': business['_id']}, {
                                '$set': {'ad_credit': Decimal128(new_money_value)}
                            })
            else:
                current_money = business['ad_credit'].to_decimal()
                new_money_value = current_money + (campaign['budget']).to_decimal() - (campaign['spend']).to_decimal()
                business_collection.update_one({'_id': business['_id']}, {
                            '$set': {'ad_credit': Decimal128(new_money_value)}
                        })

            # Delete the campaign
            campaign_result = campaigns_collection.delete_one({'_id': ObjectId(campaign_id)})

            if campaign_result.deleted_count == 1:
                # Delete the ads associated with the campaign
                ads_result = ads_collection.delete_many({'campaign_id': campaign_id})

                return Response({
                    'message': 'Campaign and associated ads deleted successfully',
                    'deleted_campaign_count': campaign_result.deleted_count,
                    'deleted_ads_count': ads_result.deleted_count
                }, status=status.HTTP_200_OK)
            else:
                return JsonResponse({'error': 'Campaign not found'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            error_message = traceback.format_exc()
            print(f"Error in delete_campaign: {error_message}")
            return JsonResponse({'error': 'Internal Server Error'}, status=500)

    return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)



@csrf_exempt
def decrease_money_view(request):
    if request.method == "POST":
        try:
            client = MongoClient(f'{settings.MONGO_URI}')
            db = client['NoteSlide']
            collection = db['Ads']

            body = json.loads(request.body.decode('utf-8'))
            ad_id = body.get('id')
            
            ad = collection.find_one({'_id': ObjectId(ad_id)})

            if ad:
                current_money = ad['spend'].to_decimal()
                new_money_value = current_money + Decimal128("0.01").to_decimal()
                collection.update_one({'_id': ObjectId(ad_id)}, {
                            '$inc': {'views': 1}, 
                            '$set': {'spend': Decimal128(new_money_value)}
                        })
                
                campaign_id = ad['campaign_id']
                collection = db['Campaigns']
                campaign = collection.find_one({'_id': ObjectId(campaign_id)})

                if ad['budget_manager'] == False:
                    current_money = campaign['spend'].to_decimal()
                    new_money_value = current_money + Decimal128("0.01").to_decimal()
                    collection.update_one(
                        {'_id': ObjectId(campaign_id)}, 
                        {
                            '$inc': {'views': 1}, 
                            '$set': {'spend': Decimal128(new_money_value)}
                        }
                    )
                else:
                    collection.update_one(
                        {'_id': ObjectId(campaign_id)}, 
                        {
                            '$inc': {'views': 1}, 
                        }
                    )

                return JsonResponse({'message': 'Money updated successfully'}, status=200)
            else:
                return JsonResponse({'error': 'Ad not found'}, status=404)
        except Exception as e:
            error_message = traceback.format_exc()
            print(f"Error in decrease_money_view: {error_message}")
            return JsonResponse({'error': 'Internal Server Error'}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def update_ad_clicks(request):
    try:
        # MongoDB connection setup
        client = MongoClient(f'{settings.MONGO_URI}')
        db = client['NoteSlide']
        collection = db['Ads']

        body = json.loads(request.body.decode('utf-8'))
        ad_id = body.get('id')

        # Fetch the note
        ad = collection.find_one({'_id': ObjectId(ad_id)})
        if ad:
            # Increment views count
            collection.update_one(
                {'_id': ObjectId(ad_id)},
                {'$inc': {'clicks': 1}}
            )

            campaign_id = ad['campaign_id']
            collection = db['Campaigns']
            collection.update_one(
                {'_id': ObjectId(campaign_id)}, 
                {
                    '$inc': {'clicks': 1}, 
                }
            )

            return JsonResponse('Success', safe=False)
        else:
            return JsonResponse({'error': 'Note not found'}, status=404)
    except Exception as e:
        error_message = traceback.format_exc()
        print(f"Error in editCampaign: {error_message}")
        return JsonResponse({'error': str(e)}, status=500)
    

class AllAdsView(View):
    def get(self, request):
        try:
            campaign_id = request.GET.get('id')
            client = MongoClient(f'{settings.MONGO_URI}')
            db = client['NoteSlide']
            collection = db['Ads']
            
            if campaign_id:
                ads = list(collection.find({'campaign_id': campaign_id}))
            else:
                ads = list(collection.find({}))
            
            formatted_ads = []
            
            for ad in ads:
                clicks = ad.get('clicks', 0)
                views = ad.get('views', 0)
                spend = ad.get('spend', Decimal128('0')).to_decimal()
                
                # Calculate metrics
                ctr = round(clicks / views, 2) if views > 0 else 0
                cpc = round(float(spend) / clicks, 2) if clicks > 0 else 0
                cpm = 10.00  # CPM is fixed at 10.00
                
                formatted_ad = {
                    '_id': str(ad['_id']), 
                    'title': ad.get('title', ''),
                    's3_path': ad.get('s3_path', ''),
                    'clicks': clicks,
                    'views': views,
                    'ctr': ctr,
                    'cpc': cpc,
                    'cpm': cpm,
                    'spend': float(spend),  # Convert Decimal to float for JSON serialization
                    'budget': float(ad.get('budget', Decimal128('0')).to_decimal()),  # Convert Decimal to float for JSON serialization
                }
                formatted_ads.append(formatted_ad)
            
            return JsonResponse(formatted_ads, safe=False)
        
        except Exception as e:
            # Log the error for debugging
            error_message = traceback.format_exc()
            print(f"Error in AllAdsView: {error_message}")
            return JsonResponse({'error': 'Internal Server Error'}, status=500)
        


@csrf_exempt
def all_campaigns(request):
    try:
        client = MongoClient(f'{settings.MONGO_URI}')
        db = client['NoteSlide']
        collection = db['Campaigns']

        body = json.loads(request.body.decode('utf-8'))
        user_id = body.get('user_id')
            
        campaigns = list(collection.find({'user_id': user_id}))
        formatted_campaigns = []
            
        for campaign in campaigns:
            spend = campaign.get('spend', Decimal128('0')).to_decimal()
            budget = campaign.get('budget', Decimal128('0')).to_decimal()
            my_id = str(campaign.get('_id'))
                
            formatted_campaign = {
                '_id': my_id,
                'title': campaign.get('title', ''),
                'spend': float(spend),  # Convert Decimal to float for JSON serialization
                'budget': float(budget),  # Convert Decimal to float for JSON serialization
            }

            formatted_campaigns.append(formatted_campaign)
            
        return JsonResponse(formatted_campaigns, safe=False)
        
    except Exception as e:
        # Log the error for debugging
        error_message = traceback.format_exc()
        print(f"Error in AllCampaignsView: {error_message}")
        return JsonResponse({'error': 'Internal Server Error'}, status=500)


@csrf_exempt
def get_campaign_by_id(request):
    try:
        client = MongoClient(f'{settings.MONGO_URI}')
        db = client['NoteSlide']
        collection = db['Campaigns']
        body = json.loads(request.body.decode('utf-8'))
        campaign_id = body.get('id')

        # Convert the campaign_id to ObjectId
        obj_id = ObjectId(campaign_id)
        
        # Query MongoDB to find the campaign with the specified _id
        campaign = collection.find_one({'_id': obj_id})

        if campaign:
            if campaign.get('budget_manager') == True:
                manager = True
            else: 
                manager = False

            formatted_campaign = {
                'budget_manager': manager,
                'id': str(campaign['_id']),
                'title': campaign.get('title', ''),
                'spend': campaign.get('spend', Decimal128('0')).to_decimal(),
                'budget': campaign.get('budget', Decimal128('0')).to_decimal(), # Example conversion to float
                'interest': campaign.get('interest', 'No Interest')
            }
            return JsonResponse(formatted_campaign)
        else:
            return JsonResponse({'error': 'Campaign not found'}, status=404)
    
    except Exception as e:
        # Log the error for debugging
        error_message = traceback.format_exc()
        print(f"Error fetching campaign from MongoDB: {error_message}")
        return JsonResponse({'error': 'Internal Server Error'}, status=500)
    


@csrf_exempt
def user_stats(request):
    client = MongoClient(f'{settings.MONGO_URI}')
    db = client['NoteSlide']
    collection = db['Notes']
    body = json.loads(request.body.decode('utf-8'))
    user_id = body.get('user_id')

    notes = list(collection.find({'user_id': user_id}))
    
    views = 0
    likes = 0
    for note in notes:
        views += note['views']
        likes += note['likes']

    stats = {
        'views': views, 
        'likes': likes
    }

    return JsonResponse(stats, safe=False)


@csrf_exempt
def business_stats(request):
    client = MongoClient(f'{settings.MONGO_URI}')
    db = client['NoteSlide']
    campaigns_collection = db['Campaigns']
    business_collection = db['Businesses']
    body = json.loads(request.body.decode('utf-8'))
    user_id = body.get('user_id')

    campaigns = list(campaigns_collection.find({'user_id': user_id}))
    business = business_collection.find_one({'_id': ObjectId(user_id)})
    views = 0
    clicks = 0
    for campaign in campaigns:
        views += campaign['views']
        clicks += campaign['clicks']

    stats = {
        'views': views, 
        'clicks': clicks,
        'ad_credit': str(business.get('ad_credit')) 
    }

    return JsonResponse(stats, safe=False)


@csrf_exempt
def clear_notifs(request):
    try:
        client = MongoClient(f'{settings.MONGO_URI}')
        db = client['NoteSlide']
        collection = db['Users']
        body = json.loads(request.body.decode('utf-8'))
        user_id = body.get('user_id')

        collection.update_one({"_id": ObjectId(user_id)}, {'$set': {'notifs': 0}})
        return JsonResponse({'ok': 'success'}, safe=False)
    except Exception as e:
        print(traceback.format_exc())
        return JsonResponse({'error': 'Internal Server Error'}, status=500)
    

@csrf_exempt
def buy_ad_credit(request):
    print('recieved')
    try:
        client = MongoClient(f'{settings.MONGO_URI}')
        db = client['NoteSlide']
        collection = db['Businesses']
        body = json.loads(request.body.decode('utf-8'))
        user_id = body.get('id')
        amount = body.get('amount')
        business = collection.find_one({'_id': ObjectId(user_id)})    

        if business:
            try:
                current_money = business['ad_credit'].to_decimal()
                new_money_value = current_money + Decimal128(amount).to_decimal()
                collection.update_one({'_id': ObjectId(user_id)}, {
                            '$set': {'ad_credit': Decimal128(new_money_value)}
                        })
            except Exception as e:
                error_message = traceback.format_exc()
                print(f"Error in decrease_money_view: {error_message}")
                return JsonResponse({'error': 'Internal Server Error'}, status=500)
    
            return JsonResponse({'message': 'Ad Credit updated successfully'}, status=200)
        else:
            return JsonResponse({'error': 'Business not found'}, status=404)
    except Exception as e:
        error_message = traceback.format_exc()
        print(f"Error in decrease_money_view: {error_message}")
        return JsonResponse({'error': 'Internal Server Error'}, status=500)
    

@csrf_exempt
def person_notes(request, username):
    client = MongoClient(f'{settings.MONGO_URI}')
    db = client['NoteSlide']
    collection = db['Notes']

    notes = list(collection.find({'username': username}))
        
    for note in notes:
        note['_id'] = str(note['_id'])  # Convert ObjectId to string

    return JsonResponse(notes, safe=False)


@csrf_exempt
def person_stats(request, username):
    client = MongoClient(f'{settings.MONGO_URI}')
    db = client['NoteSlide']
    note_collection = db['Notes']
    user_collection = db['Users']

    notes = list(note_collection.find({'username': username}))
    user = user_collection.find_one({'name': username})
    
    views = 0
    likes = 0
    for note in notes:
        views += note['views']
        likes += note['likes']

    stats = {
        'views': views, 
        'likes': likes, 
        'followers': user['followers'] if 'followers' in user else 0
    }

    return JsonResponse(stats, safe=False)



@csrf_exempt
@api_view(['POST'])
def toggle_follow(request):
    client = MongoClient(f'{settings.MONGO_URI}')
    db = client['NoteSlide']
    user_collection = db['Users']

    body = json.loads(request.body.decode('utf-8'))
    user_id = body.get('user_id')
    person_username = body.get('person')

    try:
        user = user_collection.find_one({'_id': ObjectId(user_id)})
        if user:
            following = user.get('following', [])
            if person_username not in following:
                following.append(person_username)
            else:
                following.remove(person_username)

            # Update the user's likes in the database
            user_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'following': following}}
            )
        else:
            return JsonResponse({'error': 'User not found'}, status=404)


        person = user_collection.find_one({'name': person_username})
        if person:
            user_collection.update_one(
                {'name': person_username},
                { 
                    '$inc': {'followers': 1 if person_username in following else -1}, 
                }
            )
        else:
            return JsonResponse({'error': 'Note not found'}, status=404)
        
        return JsonResponse({'following': following}, status=200)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    


# STRIPE CHECKOUT STUFF

# Set Stripe API key
stripe.api_key = settings.STRIPE_SK

# MongoDB setup
client = MongoClient(settings.MONGO_URI)
db = client["NoteSlide"]
businesses_collection = db["Businesses"]

# Stripe webhook secret
WEBHOOK_SECRET = settings.STRIPE_WEBHOOK_SECRET

@csrf_exempt
def create_checkout_session(request):
    """
    Creates a Stripe Checkout Session for one-time payments.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            product_id = data.get("product_id")
            user_id = data.get("user_id")

            # Product price mapping in cents (e.g., $5 = 500 cents)
            product_to_price_mapping = {
                "prod_RP9cgLnuHCyOSC": "price_1Qi6eJKbaPJDgRFUzMH5LC9r",   # $5
                "prod_RP9cMQUI1XUd1R": "price_1Qi6fIKbaPJDgRFU1E4Nufwt",  # $20
                "prod_RP9clgg2F0STZa": "price_1Qi6ffKbaPJDgRFUnYfhY34e",  # $50
                "prod_RP9bMSBsL7kw2C": "price_1Qi6fzKbaPJDgRFUUQMXkjkd", # $100
                "prod_RP9bqqcFCSxzGv": "price_1Qi6gMKbaPJDgRFUwFH94elJ", # $500
                "prod_RP9b8t7JTmE4G5": "price_1Qi6gyKbaPJDgRFUCiHYRkJo" # $1500
            }

            if product_id not in product_to_price_mapping:
                return JsonResponse({"error": "Invalid Product ID"}, status=400)

            # Create a Stripe Checkout Session
            session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                line_items=[
                    {
                        "price": product_to_price_mapping[product_id],
                        "quantity": 1,
                    }
                ],
                mode="payment",  # One-time payment mode
                success_url="https://note-slide.com/business",
                cancel_url="https://note-slide.com/business",
                metadata={
                    "user_id": user_id,  # Attach user ID as metadata
                    "product_id": product_id,  # Attach product ID as metadata
                }
            )

            return JsonResponse({"url": session.url})

        except Exception as e:
            print(traceback.format_exc())
            return JsonResponse({"error": str(e)}, status=400)


@csrf_exempt
def stripe_webhook(request):
    """
    Handles Stripe webhook events.
    """
    payload = request.body
    sig_header = request.META['HTTP_STRIPE_SIGNATURE']

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, WEBHOOK_SECRET
        )
    except stripe.error.SignatureVerificationError as e:
        # Signature doesn't match
        return JsonResponse({'error': 'Invalid signature'}, status=400)

    # Handle checkout.session.completed
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        handle_checkout_session(session)

    return JsonResponse({"status": "success"}, status=200)


def handle_checkout_session(session):
    """
    Processes the checkout session completion event.
    """
    user_id = session["metadata"].get("user_id")
    product_id = session["metadata"].get("product_id")

    # Map product_id to ad credits
    product_to_credit = {
        "prod_RP9cgLnuHCyOSC": 5,
        "prod_RP9cMQUI1XUd1R": 20,
        "prod_RP9clgg2F0STZa": 50,
        "prod_RP9bMSBsL7kw2C": 100,
        "prod_RP9bqqcFCSxzGv": 500,
        "prod_RP9b8t7JTmE4G5": 1500,
    }

    credit = product_to_credit.get(product_id, 0)
    # ad_credit_value = Decimal128(Decimal(credit)).to_decimal()

    if user_id:
        business = businesses_collection.find_one({'_id': ObjectId(user_id)})
    else:
        print("no user id")    

    if business and credit > 0:
        try:
            current_money = business['ad_credit'].to_decimal()
            new_money_value = current_money + Decimal128(str(credit)).to_decimal()
            businesses_collection.update_one({'_id': ObjectId(user_id)}, {
                        '$set': {'ad_credit': Decimal128(new_money_value)}
                    })
            print(f"Added {credit} credits to user {user_id}.")
        except Exception as e:
            print(f"Failed to update MongoDB: {e}")
