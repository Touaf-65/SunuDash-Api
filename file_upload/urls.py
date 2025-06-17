from django.urls import path
from .views import UploadFileView1, FileListView, StatisticalFileListView, RecapFileListView, UploadAndValidateFiles

urlpatterns = [
    path('upload1/', UploadFileView1.as_view(), name='file_list'),
    path('', FileListView.as_view(), name='files_list'),
    path('recap_files/', RecapFileListView.as_view(), name='recap_files'),
    path('statistical_files/', StatisticalFileListView.as_view(), name='statistical_files'),

    path('upload_and_validate/', UploadAndValidateFiles.as_view(), name='upload_and_validate_files'),
]