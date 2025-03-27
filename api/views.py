from api import serializer as api_serializer
from api import models as api_models
from rest_framework.permissions import AllowAny, IsAuthenticated
from .models import Contact
from rest_framework import generics
from rest_framework import status
from rest_framework.response import Response
from .models import Contact
from django.views.decorators.csrf import csrf_exempt
import json
from django.http.response import JsonResponse
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings

class ContactListView(generics.ListCreateAPIView):
    serializer_class = api_serializer.ContactSerializer
    queryset = api_models.Contact.objects.all()
    
    def create(self, request):
        name = request.data.get('name')
        email = request.data.get('email')
        subject = request.data.get('subject')
        s_link = request.data.get('s_link')
        message = request.data.get('message')
        
        new_contact = Contact.objects.create(
            name=name,
            email=email,
            subject=subject,
            s_link=s_link,
            message=message
        )
        
        # Send HTML email to owner
        owner_email = "Sheryarsatti6@gmail.com"
        owner_subject = f"New Contact Form Submission: {subject}"
        
        # Render both text and HTML versions
        text_content = render_to_string('email/contact_owner_email.txt', {
            'name': name,
            'email': email,
            'subject': subject,
            's_link': s_link,
            'message': message,
        })
        
        html_content = render_to_string('email/contact_owner_email.html', {
            'name': name,
            'email': email,
            'subject': subject,
            's_link': s_link,
            'message': message,
        })
        
        email_msg = EmailMultiAlternatives(
            owner_subject,
            text_content,
            settings.EMAIL_HOST_USER,
            [owner_email]
        )
        email_msg.attach_alternative(html_content, "text/html")
        email_msg.send()
        
        # Send HTML confirmation email to the contact
        if email:
            contact_subject = f"Thank you for contacting us: {subject}"
            
            contact_text = render_to_string('email/contact_confirmation.txt', {
                'name': name,
                'subject': subject,
                'email':email
            })
            
            contact_html = render_to_string('email/contact_confirmation.html', {
                'name': name,
                'subject': subject,
                'email': email,
            })
            
            contact_email = EmailMultiAlternatives(
                contact_subject,
                contact_text,
                settings.EMAIL_HOST_USER,
                [email]
            )
            contact_email.attach_alternative(contact_html, "text/html")
            contact_email.send()

        return JsonResponse({
        "success": True,
        "status": status.HTTP_201_CREATED,
        "message": "Contact form submitted successfully"
    }, status=status.HTTP_201_CREATED)
        # return Response(status=status.HTTP_201_CREATED)


@csrf_exempt
def verify_transaction(request):
    if request.method == "POST":
        data = json.loads(request.body)
        transaction_id = data.get("transaction_id")
        order_id = data.get("order_id")
        
        # Create transaction record
        api_models.TransactionRecord.objects.create(
            transaction_id=transaction_id,
            order_id=order_id
        )
        
        # Send HTML email to owner about the transaction
        owner_email = "Sheryarsatti6@gmail.com"
        subject = f"New Transaction Adde for verifcation: {transaction_id}"
        
        text_content = render_to_string('email/transaction_notification.txt', {
            'transaction_id': transaction_id,
            'order_id': order_id,
        })
        
        html_content = render_to_string('email/transaction_notification.html', {
            'transaction_id': transaction_id,
            'order_id': order_id,
        })
        
        email_msg = EmailMultiAlternatives(
            subject,
            text_content,
            settings.EMAIL_HOST_USER,
            [owner_email]
        )
        email_msg.attach_alternative(html_content, "text/html")
        email_msg.send()
        
        return JsonResponse({"status": "success", "message": "Payment verified!"}, status=status.HTTP_201_CREATED)