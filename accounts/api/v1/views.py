from django.http import Http404
from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.api.v1.serializers import UserSerailizers
from accounts.models import User


# ./manage.py drf_create_token admin
class UserView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = (IsAuthenticated,)
    def get(self, request, format=None):

        user = User.objects.all()
        serializer = UserSerailizers(user, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        serializer = UserSerailizers(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class UserDetail(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = (IsAuthenticated,)
    def get_object(self, pk):
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        user = self.get_object(pk)
        serializer = UserSerailizers(user)
        return Response(serializer.data)

    def put(self, request, pk, format=None):
        user = self.get_object(pk)
        serializer = UserSerailizers(User, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        user = self.get_object(pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)