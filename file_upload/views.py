from django.shortcuts import render
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from users.permissions import IsSuperUser
from .models import File
from .serializers import FileSerializer

class FileListView(APIView):
    # permission_classes = [IsAuthenticated, IsSuperUser]

    def get(self, request):
        files = File.objects.all().order_by("-uploaded_at")
        serializer = FileSerializer(files, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class StatisticalFileListView(ListAPIView):
    # permission_classes = [IsAuthenticated]
    
    def get(self, request):
        files = File.objects.filter(file_type='stat').order_by("-uploaded_at")
        serializer = FileSerializer(files, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class RecapFileListView(ListAPIView):
    # permission_classes = [IsAuthenticated]
    
    def get(self, request):
        files = File.objects.filter(file_type='recap').order_by("-uploaded_at")
        serializer = FileSerializer(files, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class UploadFileView1(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = FileSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

