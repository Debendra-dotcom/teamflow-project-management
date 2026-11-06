from .models import User
from .serializers import (UserSerializer, RegisterSerializer, LoginSerializer,
                          LogoutSerializer, TokenPairSerializer, ErrorResponseSerializer)
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import ScopedRateThrottle
from drf_spectacular.utils import extend_schema, OpenApiExample, OpenApiResponse

class UserViewSet(ModelViewSet):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]  

    def get_queryset(self):
        user = self.request.user
        if user.role == "admin":
            return User.objects.all()
        return User.objects.filter(id=user.id)


class UserRegistrationView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'register'
    @extend_schema(
        request=RegisterSerializer,
        responses={201: UserSerializer, 400: OpenApiResponse(ErrorResponseSerializer, description='Validation error')},
        examples=[OpenApiExample('Registration request', value={
            'username': 'alex', 'email': 'alex@example.com', 'password': 'StrongPass123!',
            'password_confirmation': 'StrongPass123!',
        }, request_only=True)],
        description='Creates a member account. Password confirmation is optional for backwards compatibility.',
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
#_______________________________________________________________________________________________
class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'login'
    @extend_schema(
        request=LoginSerializer,
        responses={200: TokenPairSerializer, 400: OpenApiResponse(ErrorResponseSerializer, description='Invalid credentials')},
        examples=[OpenApiExample('Login request', value={'username': 'alex', 'password': 'StrongPass123!'}, request_only=True)],
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']

        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])

        refresh = RefreshToken.for_user(user)

        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        }, status=status.HTTP_200_OK)
#_____________________________________________________________________________
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    @extend_schema(
        request=LogoutSerializer,
        responses={205: OpenApiResponse(description='Refresh token blacklisted'), 400: OpenApiResponse(ErrorResponseSerializer), 401: OpenApiResponse(ErrorResponseSerializer)},
        examples=[OpenApiExample('Logout request', value={'refresh': '<refresh-token>'}, request_only=True)],
    )
    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        refresh_token = serializer.validated_data['refresh']

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()  # بلاک کردن توکن
            return Response({"detail": "Logout successful."}, status=status.HTTP_205_RESET_CONTENT)
        except TokenError:
            return Response({"detail": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
#_____________________________________________________________________________
