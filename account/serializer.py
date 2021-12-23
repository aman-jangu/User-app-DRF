from rest_framework_jwt.settings import api_settings
JWT_PAYLOAD_HANDLER = api_settings.JWT_PAYLOAD_HANDLER
JWT_ENCODE_HANDLER = api_settings.JWT_ENCODE_HANDLER
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from rest_framework import serializers
from account.models import User


class UserSerializer(serializers.HyperlinkedModelSerializer):
    username = serializers.CharField(label="username field",
                                     required=True, allow_null=False,
                                     allow_blank=False)

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password','address')
        extra_kwargs = {'password': {'write_only': False}}

    def create(self, validated_data):
        password = validated_data.pop('password')
        try:
            if User.objects.filter(username__iexact=User(**validated_data).username).exists():
                raise serializers.ValidationError("username already exists")
        except Exception as e:
                error = {'message': ",".join(e.args) if len(e.args) > 0 else 'Unknown Error'}
                raise serializers.ValidationError(error)
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user


class UserLoginSerializer(serializers.Serializer):

    email = serializers.CharField(max_length=50)
    password = serializers.CharField(max_length=128, write_only=True)
    token = serializers.CharField(max_length=255, read_only=True)

    def validate(self, data):
        email = data.get("email", None)
        password = data.get("password", None)
        try:
            if not User.objects.filter(email__iexact=email).exists():
                raise serializers.ValidationError("email does not exist")
        except Exception as e:
            error = {'message': ",".join(e.args) if len(e.args) > 0 else 'Unknown Error'}
            raise serializers.ValidationError(error)

        user_obj = User.objects.get(email=email)
        username = user_obj.username
        user = authenticate(username=username, password=password)
        if user is None:
            error = {'message': "A user with this password is not found."}
            raise serializers.ValidationError(error)
        try:
            payload = JWT_PAYLOAD_HANDLER(user)
            jwt_token = JWT_ENCODE_HANDLER(payload)
            update_last_login(None, user)
        except User.DoesNotExist:
            raise serializers.ValidationError(
                'User with given email and password does not exists'
            )

        return {
            'email': user.email,
            'token': jwt_token
        }



