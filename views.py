from rest_framework.viewsets import GenericViewSet
from rest_framework.permissions import IsAuthenticated
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin, CreateModelMixin
from django.contrib.auth import get_user_model
from users.models import User
from users.serializer import UserSerializer, RegisterSerializer
from rest_framework.throttling import ScopedRateThrottle, AnonRateThrottle
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import GenericAPIView, ListAPIView, ListCreateAPIView
from rest_framework.mixins import CreateModelMixin, ListModelMixin, UpdateModelMixin, RetrieveModelMixin, DestroyModelMixin
from rest_framework.viewsets import GenericViewSet
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.core.validators import ValidationError
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from .serializer import PasswordResetConfrimSerializer

from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django_filters.rest_framework import DjangoFilterBackend
from products.pagination import ProductPaginaton
from rest_framework.throttling import ScopedRateThrottle, AnonRateThrottle
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import GenericAPIView, ListAPIView, ListCreateAPIView
from rest_framework.mixins import CreateModelMixin, ListModelMixin, UpdateModelMixin, RetrieveModelMixin, DestroyModelMixin
from rest_framework.viewsets import GenericViewSet
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser

User = get_user_model()


class UserViewSet(ListModelMixin, RetrieveModelMixin, GenericViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    
class UserRegisterViewSet(CreateModelMixin,GenericViewSet):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    
class ResetPasswordView(CreateModelMixin, GenericViewSet):
    serializer_class = ResetPasswordSerializer
    
    
    def create(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)
            
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            reset_url = request.build_absolute_uri(
                reverse('password_reset_confrim', kwargs={'uidb64' : uid, 'token':token})
            )
            reset_url = f'http://127:0:0:1/reset_password_confirm/{uid}/{token}/'
            
            send_mail(
                'parolis agdgena',
                f'daawiret links resetistvis {reset_url}',
                'ragaca@gmail.com',
                [user.email],
                fail_silently = False
            )
            
            return Response({'message': 'gaigzavna'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class ResetPasswordView(CreateModelMixin, GenericViewSet):
    serializer_class = PasswordResetConfrimSerializer
    
    @swagger_auto_schema(
        manual_parameters=(
          openapi.Parameter('uidb64', openapi.IN_PATH, description='User Id (Base64 Encoded)', type=openapi.TYPE_STRING),
          openapi.Parameter('token', openapi.IN_PATH, description='Pasword Reset Token', type=openapi.TYPE_STRING)
        )
    )
    
    def create(self, request, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'completed'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_401_BAD_REQUEST)