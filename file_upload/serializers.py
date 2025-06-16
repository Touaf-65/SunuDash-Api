from rest_framework import serializers
from .models import File

class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = File
        fields = ['id', 'user', 'file', 'uploaded_at', 'size', 'file_type']
        read_only_fields = ['id', 'user', 'uploaded_at', 'size']
