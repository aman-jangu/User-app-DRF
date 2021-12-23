from rest_framework import viewsets, status
from rest_framework.decorators import api_view
from rest_framework.permissions import AllowAny
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.response import Response
from account.models import User
from account.serializer import UserSerializer, UserLoginSerializer
from account.permissions import IsLoggedInUserOrAdmin, IsAdminUser
from rest_framework.generics import RetrieveAPIView
from rest_framework.views import APIView
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.utils.crypto import get_random_string
from rest_framework_jwt.settings import api_settings
JWT_PAYLOAD_HANDLER = api_settings.JWT_PAYLOAD_HANDLER
JWT_ENCODE_HANDLER = api_settings.JWT_ENCODE_HANDLER
from django.contrib.auth.models import update_last_login
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.backends import TokenBackend
from rest_framework.exceptions import ValidationError

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get_permissions(self):
        permission_classes = []
        if self.action == 'create':
            permission_classes = [AllowAny]
        elif self.action == 'retrieve' or self.action == 'update' or self.action == 'partial_update':
            permission_classes = [IsLoggedInUserOrAdmin]
        elif self.action == 'list' or self.action == 'destroy':
            permission_classes = [IsAdminUser]
        return [permission() for permission in permission_classes]


@api_view(['GET'])
def check_user(request):
    """
    check if user exists or not
    :param request:
    :type request:
    :return: true is user exists
    :rtype: bool
    """
    username = request.GET.get('username')
    email = request.GET.get('email')
    if not username and not email:
        return Response({
            'message': "username or email missing.",
        }, status.HTTP_400_BAD_REQUEST)

    try:
        User.objects.get(username=username)
    except ObjectDoesNotExist:
        try:
            User.objects.get(email=email)
        except ObjectDoesNotExist:
            return Response({
                'message': "email and username does not exists.",
            }, status.HTTP_400_BAD_REQUEST)

    return Response({
        'message': "username or email exists.",
    }, status.HTTP_200_OK)


class UserRegistrationView(APIView):
    serializer_class = UserSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.initial_data['confirm_password'] != serializer.initial_data['password']:
            return Response({
                "message": "password didn't match"
            }, status=status.HTTP_400_BAD_REQUEST)
        if not serializer.is_valid():
            try:
                if User.objects.filter(
                        email=serializer.data['email']
                ).exists():
                    raise serializers.ValidationError("email already exists")
            except Exception as e:
                error = {'message': ",".join(e.args) if len(e.args) > 0 else 'Unknown Error'}
                raise serializers.ValidationError(error)
        serializer.is_valid(
            raise_exception=True
        )
        serializer.save()

        user_obj = User.objects.get(
            email=serializer.data['email']
        )
        response = {
            'usersData': {
                "id": user_obj.id,
                "username": user_obj.username,
                "email": user_obj.email,
            },
            'message': 'User registered successfully',
            'status': 'True',
        }
        status_code = status.HTTP_201_CREATED
        return Response(response, status=status_code)


class UserLoginView(RetrieveAPIView):

    permission_classes = (AllowAny,)
    serializer_class = UserLoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_obj = User.objects.get(
            email=serializer.data['email']
        )

        response = {
            'usersData': {
                "id": user_obj.id,
                "username": user_obj.username,
                "email":user_obj.email,
                },
            'message': 'User logged in successfully',
            'status': 'True',
            'accessToken': serializer.data['token'],
            }
        status_code = status.HTTP_200_OK

        return Response(response, status=status_code)


class ChangePasswordViewSet(RetrieveAPIView):

    permission_classes = (IsLoggedInUserOrAdmin,)

    def post(self, request):
        new_password = request.data['new_password']
        confirm_password = request.data['confirm_password']
        current_password = request.data['current_password']

        #authenticate old password
        user = authenticate(username=request.user.username, password=current_password)
        if user is None:
            return Response(
                {"message": "current password didn't match!"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if new_password == confirm_password:
           # reset password
           request.user.set_password(confirm_password)
           request.user.save()
        else:
            return Response(
                {"message": "password didn't match !"},
                status = status.HTTP_400_BAD_REQUEST
            )

        return Response(
            {"message": "Password Reset Successful!"},
            status=status.HTTP_200_OK
        )


class UpdateUserProfile(RetrieveAPIView):

    permission_classes = (IsLoggedInUserOrAdmin,)

    def post(self, request):
        user = request.user
        validated_data = request.data
        username = validated_data.get('username', user.username)
        if user.username != username:
            user.username = validated_data.get('username', user.username)
            try:
                if User.objects.filter(
                        username__iexact=user.username
                ).exists():
                    return Response({
                        "message":"username already exist !"},
                        status = status.HTTP_400_BAD_REQUEST
                    )
            except Exception as e:
                error = {'message': ",".join(e.args) if len(e.args) > 0 else 'Unknown Error'}
                return Response({
                    "message": error },
                    status=status.HTTP_400_BAD_REQUEST
                )
        user.save()
        return Response({
            "user_data": "",
            'message':"user updated successfully !"},
            status=status.HTTP_200_OK
        )

class UserDetails(APIView):
    def get(self, request):
        email = request.GET.get("email")
        user_obj = User.objects.get(email=email)
        print(user_obj)
        details = {
            "username": user_obj.username,
            "email": user_obj.email,
            "address": user_obj.address
        }
        return Response({
            "status": True,
            "user_details": details
        })



def user_info(token):

    data = {'token': token}
    try:
        valid_data = TokenBackend(algorithm='HS256').decode(token, verify=False)
        print(valid_data,"p")
        user_id = valid_data['user_id']
        return user_id

    except ValidationError as v:
        return -1